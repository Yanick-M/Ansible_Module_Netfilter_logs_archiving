#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 [Yanick-M]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: archiving_script
short_description: Create a script to archive Netfilter logs on a dedicated machine
description:
    - Create an archiving script based on a template list that will make an archive of rotated Netfilter logs files and upload it on a dedicated machine.
    - Each client has it own directory in the repo, and archives are stored in directories composed of months and years ("december2020/").
    - The upload is done with ssh and rsync (to remove archive just after).
version_added: "3.7.3"
options:
    host:
        description:
            - the hostname or IP address of the dedicated machine where Netfilter logs archives are going to be centralize.
        needed: with present state
    username:
        description:
            - the username used by ssh connection.
        needed: with present state
    password:
        description:
            - the username password (configure with no_log option True).
        needed: with present state
    ARCHIVING_COMMANDS_LIST:
        description:
            - a list of the archiving script template.
        needed: with present state
        example: https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/logs_transfer/vars/main.yml
    state:
        description:
            - Indicates if you want to create or remove the archiving script.
        default: present
        choices: {present, absent}
requirements:
    - ssh
    - sshpass
    - tar
    - rsync
    - python3
    - python3-paramiko
    - python3-scp
author: "Yanick-M"
notes:
    - THIS MODULE REQUIRES PRIVILEGES !!!
'''

EXAMPLES = '''
- name: "create archiving script"
  hosts: All
  tasks:
    - name: "Use my module"
      archiving_script:
        state: "present"
        username: "{{username}}"
        password: "{{password}}"
        host: "{{host}}"
        ARCHIVING_COMMANDS_LIST: "{{ARCHIVING_COMMANDS_LIST}}"

- name: "remove logrotate conf file for Netfilter logs files"
  hosts: All
  tasks:
    - name: "Use my module"
      archiving_script:
        state: "absent"

- name: "configure logrotate for Netfilter logs files with all vars defined"
  hosts: All
  tasks:
    - name: "Use my module"
      archiving_script:
        state: "present"
        username: "aic"
        password: "Azerty123&"
        host: "ServerCentral"
        SSH_PATH: "/root/.ssh/"
        REMOTE_PATH: "/LogsArchiving_REPO/"
        RSA_FILE: "id_rsa_archiving"
        PUB_RSA_FILE: "id_rsa_archiving.pub"
        ARCHIVING_SCRIPT_PATH: "/root/"
        ARCHIVING_SCRIPT_NAME: "netfilter_logs_archiving.sh"
        ARCHIVING_COMMANDS_LIST: [...]        
'''
RETURN = '''
Nothing more than changed and a result message.
'''

import os, stat, paramiko
from ansible.module_utils.basic import AnsibleModule
from scp import SCPClient

# Define module user-defined exceptions and errors
class Error(Exception):
    ''' Base class for errors that require to stop module execution '''

    def no_privileges(self, module):
        ''' raised when an action need privileges '''
        module.fail_json(changed = False, msg = "\033[31mMust be run as root !\033[0m")

    def file_missing(self, path, name, module):
        ''' raised when a file does not exists on the remote host '''
        module.fail_json(changed = False, msg = "\033[31mThe file {} in \"{}\" is missing !\033[0m".format(path, name))

    def unable_to_write(self, path, name, module):
        ''' raised when a file can't be created or modified on the remote host '''
        module.fail_json(changed = False, msg = "\033[31m Can't write the file {} in \"{}\" !\033[0m".format(path, name))

    def fatal_error(self, module):
        ''' raised when a unknown problem occurs '''
        module.fail_json(changed = False, msg = "\033[31mFatal error, report bug !\033[0m")

    def empty_list(self, module):
        ''' raised when a required list var is missing'''
        module.fail_json(changed = False, msg = "\033[31mA required list var is missing !\033[0m")

class MyFileNotFound(Error):
    ''' Raised when a file is not found on the remote host '''
    pass
class ReadingFailure(Error):
    ''' Raised when a file is not accessible on the remote host '''
    pass
class WritingFailure(Error):
    ''' Raised when a file can't be writed or modified on the remote host '''
    pass
class EmptySearch(Error):
    ''' Raised when data comparison is null '''
    pass
class ServiceFailure(Error):
    ''' Raised when a problem occurs with restarting a service '''
    pass
class NoUpDateNeeded(Error):
    ''' Raised when a task don't need an update'''
    pass

############################################################################################################################################################
############################################################################################################################################################

# Define common functions
def read_file(path, name):
    ''' To see if a file exists on the remote host and return his content in a list '''

    try:
        my_file = open(path + name, "r")
        liste = [i[:-1] for i in my_file]
        my_file.close()
    except FileNotFoundError:
        raise MyFileNotFound
    except IOError:
        raise ReadingFailure
    
    return(liste)

def write_file(path, name, data):
    ''' To write data in a file on the remote host '''

    try:
        with open(path + name, "w") as fichier:
            for line in data:
                fichier.write("{}\n".format(line))
    except IOError:
        raise WritingFailure

def implement_file(path, name, rights):
    ''' To change file permissions '''

    try:
        os.chmod(path + name, rights)
    except FileNotFoundError:
        raise MyFileNotFound
    except PermissionError:
        raise WritingFailure


############################################################################################################################################################
############################################################################################################################################################

class ssh:
    ''' Class for ssh operations '''

    def __init__(self, module):
        ''' Initialize the object '''

        self.host = module.params.get('host')
        self.client = None
        self.scp = None
        self.username = module.params.get('username')
        self.password = module.params.get('password')
        self._connect(module)

    def _connect(self, module):
        ''' Initialize the connection '''
        
        try:
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._check_rsa_keys(module)
            self.client.connect(self.host, username = self.username, pkey = self.ssh_key, timeout=3)
            self.scp = SCPClient(self.client.get_transport())
        except:
            pass
        finally:
            return self.client
    
    def _check_rsa_keys(self, module):
        ''' Check if rsa keys exist on the remote host (needed for ssh operations with no password input) '''

        self.rsa_key = module.params.get('RSA_FILE')
        self.pub_rsa_key = module.params.get('PUB_RSA_FILE')
        self.path_rsa_keys = module.params.get('SSH_PATH')
        try:
            read_file(self.path_rsa_keys, self.rsa_key)
            read_file(self.path_rsa_keys, self.pub_rsa_key)
            self.ssh_key = paramiko.RSAKey.from_private_key_file("{}{}".format(self.path_rsa_keys, self.rsa_key))
        except MyFileNotFound as exc:
            self._create_rsa_keys(module)
            self.ssh_key = paramiko.RSAKey.from_private_key_file("{}{}".format(self.path_rsa_keys, self.rsa_key))
        except ReadingFailure as exc:
            raise Error.no_privileges(ReadingFailure, module)

    def _create_rsa_keys(self, module):
        ''' Create rsa keys on the remote host and copy the id on the target machine '''

        self.rights = stat.S_IREAD|stat.S_IWRITE

        os.system("rm \"{0}{1}\" > /dev/null 2>&1 | ssh-keygen -b 4096 -m PEM -f \"{0}{1}\" -N \"\" > /dev/null 2>&1".format(self.path_rsa_keys, self.rsa_key))

        try:
            implement_file(self.path_rsa_keys, self.rsa_key, self.rights)
            implement_file(self.path_rsa_keys, self.pub_rsa_key, self.rights)
        except FileNotFoundError as exc:
            pass
        except WritingFailure as exc:
            raise Error.no_privileges(IOError, module)
        
        os.system("echo 'Host {0}\n     IdentityFile {1}{2}' >> \"{1}config\"".format(self.host, self.path_rsa_keys, self.rsa_key))

        result = os.system("sshpass -p \"{}\" ssh-copy-id -o StrictHostKeyChecking=no -i \"{}{}\" {}@{} > /dev/null 2>&1".format(self.password, self.path_rsa_keys, self.pub_rsa_key, self.username, self.host))
        if result == 256:
            module.warn("Unable to tranfer id on {}, problem to study ! Maybe the name of the target machine or the name of the key are incorrect".format(host.upper()))
        elif result == 1536:
            module.warn("The username of the target machine or his password on {} are incorrect !".format(host.upper()))

    def disconnect(self):
        ''' Close the ssh connection with the target machine '''
        
        self.client.close()
        self.scp.close()

    def _exec_command(self, command, module):
        ''' Execute a specified command on the target machine '''

        if self.client is None:
            self.client == self.__connect(module)
        self.client.exec_command(command)

    def download_file(self, path, remote_path, name, module):
        ''' Download a file from the target machine '''
    
        try:
            if self.client is None:
                self.client = self.__connect()
            self.scp.get('{}{}'.format(remote_path, name), '{}{}'.format(path, name))
        except:
            module.warn("-----Unable to download the file {} from {}-----".format(name, self.host.upper()))

    def upload_file(self, path, dest_path, name, module):
        ''' Transfer a file on the target machine (create directories if they don't exists but not possible on root) '''

        try:
            if self.client is None:
                self.client = self.__connect()
            self._exec_command("mkdir -p {}".format(dest_path), module)
            self.scp.put('{}{}'.format(path, name), recursive=True, remote_path = dest_path)
        except:
            module.warn("-----Unable to upload the file {} on {}-----".format(name, self.host.upper()))

############################################################################################################################################################
############################################################################################################################################################

class archives:
    ''' Class to manage archiving script '''

    def __init__(self, module):
        ''' Initialize the object '''
        
        self.name = module.params.get('ARCHIVING_SCRIPT_NAME')
        self.path = module.params.get('ARCHIVING_SCRIPT_PATH')
        self.commands = module.params.get('ARCHIVING_COMMANDS_LIST')
        self._read(module)

    def _read(self, module):
        ''' Check if the archiving script exists '''

        try:
            self.file_content = read_file(self.path, self.name)
            self.existing_file = True
        except MyFileNotFound as exc:
            self.existing_file = False
        except ReadingFailure as esc:
            raise Error.privileges(ReadingFailure)

    def search(self, value):
        ''' Check if a value exists in the content of the archiving script '''

        result = False
        for line in self.file_content:
            if line.find(value) >= 0:
                result = True
        if result is False:
            raise EmptySearch

    def create_commands(self, module, link):
        ''' Create the content of the script '''
        
        self.commands.insert(2, "host={}".format(link.host))
        self.commands.insert(2, "user={}".format(link.username))

    def write_commands(self, module):
        ''' Write the content in a file on the remote host '''

        try:
            write_file(self.path, self.name, self.commands)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure, module)

        self.implement(module)

    def implement(self, module):
        ''' Modify the permisssion of the archiving script '''

        rights = stat.S_IRWXU
        try:
            implement_file(self.path, self.name, rights)
        except MyFileNotFound as exc:
            raise Error.erreurfatale(MyFileNotFound, module)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure, module)

############################################################################################################################################################
############################################################################################################################################################

def create_script(module):
    
    # Objects establishing for the archiving script and rsa key generation
    job = archives(module)
    link = ssh(module)

    # If the archiving script exists, checking if the username and the target machine are good
    # Yes, no change needed
    # No, updating the script
    if not job.commands:
        raise Error.empty_list(job.commands, module)
    elif job.existing_file is True:
        try:
            job.search(link.username)
            job.search(link.host)
            module.exit_json(changed = False, msg = "Archiving script already exists.")
        except EmptySearch as exc:
            job.create_commands(module, link)
            job.write_commands(module)
            return True, "Archiving script has been updated with new host or user."
    # If not, creating the script
    else:
        job.create_commands(module, link)
        job.write_commands(module)
        return True, "Archiving script has been created."


def remove_script(module):
    
    # Objects establishing for the archiving script
    job = archives(module)

    if job.existing_file is True:
        try:
            os.remove(job.path + job.name)
            return True, "Archiving script has been removed."
        except IOError:
            raise Error.no_privileges(IOError, module)
    else:    
        return False, "Archiving script has not been found."
    

def main():
    ''' Check if the archiving script and executing task already exist, update, create or remove them if necessary '''

    fields = {
            "username": {"default": "", "type": "str"},
            "password": {"default": "", "no_log": True, "type": "str"},
            "host": {"default": "", "type": "str"},
            "SSH_PATH": {"default": "/root/.ssh/", "type": "str"},
            "REMOTE_PATH": {"default": "/LogsArchiving_REPO/", "type": "str"},
            "RSA_FILE": {"default": "id_rsa_archiving", "type": "str"},
            "PUB_RSA_FILE": {"default": "id_rsa_archiving.pub", "type": "str"},
            "ARCHIVING_SCRIPT_PATH": {"default": "/root/", "type": "str"},
            "ARCHIVING_SCRIPT_NAME": {"default": "netfilter_logs_archiving.sh", "type": "str"},
            "ARCHIVING_COMMANDS_LIST": {"default": [], "type": "list"},
            "state": {
                "default": "present", 
                "choices": ['present', 'absent'],  
                "type": 'str' 
                }
            }
    
    module = AnsibleModule(argument_spec = fields)

    choice_map = {
        "present": create_script,
        "absent": remove_script
        }

    module = AnsibleModule(argument_spec = fields)

    has_changed, result = choice_map.get(module.params['state'])(module)
    module.exit_json(changed=has_changed, msg=result)

if __name__ == '__main__':

    main()