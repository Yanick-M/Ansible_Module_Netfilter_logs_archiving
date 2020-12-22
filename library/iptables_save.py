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
module: iptables_save
short_description: Save firewall rules
description:
    - Make a save of the netfilter rules with IPtables is going to be done in "/etc/init.d/" and copy the save file on a remote server with scp. The save filename is generated with the prefix send by Ansible and the hostname.
version_added: "3.7.3"
options:
    state:
        description:
            - Indicates if you want to save or remove save file.
        default: present
        choices: {present, absent}
requirements:
    - ssh
    - sshpass
    - python3-paramiko
    - python3-scp
    - iptables
author: "Yanick-M"
notes:
    - THIS MODULE REQUIRES PRIVILEGES !!!
'''

EXAMPLES = '''
- name: "saving IPtables Rules"
  hosts: All
  tasks:
    - name: "Use my module"
      iptables_save:
        state: present
        username: "{{username}}"
        password: "{{password}}"
        host: "{{host}}"

- name: "remove IPtables save"
  hosts: All
  tasks:
    - name: "Use my module"
        iptables_save
        state: absent

- name: "saving IPtables Rules without a copy on a remote machine"
  hosts: All
  tasks:
    - name: "Use my module"
      iptables_save:
        state: present

- name: "saving IPtables Rules with all vars defined"
  hosts: Router
  tasks:
    - name: "Use my module"
      iptables_save:
        state: present
        username: "aic"
        password: "Azerty123&"
        host: "ServerCentral"
        IPTABLES_PREFIX: "firewall_"
        INITD_PATH: "/etc/init.d/"
        RSA_FILE: "id_rsa_archiving"
        PUB_RSA_FILE: "id_rsa_archiving.pub"
        REMOTE_PATH: "/LogsArchiving_REPO/"
        SSH_PATH: "/root/.ssh/"
'''
RETURN = '''
Nothing more than changed and a result message.
'''

import os, socket, stat, paramiko
from ansible.module_utils.basic import *
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

class iptables:
    ''' Class to manage iptables save '''
    
    def __init__(self, module):
        ''' Initialize the object '''
        
        self.name = module.params.get("IPTABLES_PREFIX") + socket.gethostname()
        self.path = module.params.get('INITD_PATH')
        self.remote_path = module.params.get('REMOTE_PATH') + socket.gethostname() + "/"
        self._read(module)
        
    def _read(self, module):
        ''' Check if a save exists on the remote host ''' 
        
        try:
            self.rules_list = read_file(self.path, self.name)
            self.existing = True
        except MyFileNotFound as exc:
            self.existing = False
        except ReadingFailure as esc:
            raise Error.privileges(ReadingFailure, module)

    def download(self, link, module):
        ''' Download a copy of a previous save on the remote host from the target machine '''
        
        link.download_file(self.path, self.remote_path, self.name, module)
        self._read(module)

    def save(self, module):
        ''' Save the iptables rules on the remote host '''

        os.system("/usr/sbin/iptables-save > \"{}{}\"".format(self.path, self.name))
        self._read(module)

    def upload(self, link, module):
        ''' Upload a copy of the save from the remote host to the target machine '''

        link.upload_file(self.path, self.remote_path, self.name, module)

############################################################################################################################################################
############################################################################################################################################################

def make_save(module):
    
    # Objects establishing for iptables save and the ssh connection
    job = iptables(module)
    link = ssh(module)

    # If a save has been found in init.d directory, no change needed
    if job.existing is True:
        return False, "Netfilter rules are already saved."
    else:
        # No, try to download a copy or make the save
        job.download(link, module)
        if job.existing is True:
            return False, "Netfilter save has been downloaded from remote server."
        else:
            job.save(module)
            if job.existing is True:
                job.upload(link, module)
                return True, "Netfilter rules have been saved"
            else:
                return False, "Unable to save Netfilter rules" 

def remove_save(module):
    
    # Objects establishing for iptables save and the ssh connection
    job = iptables(module)

    if job.existing is True:
        try:
            os.remove(job.path + job.name)
            return True, "IPtables save has been removed."
        except IOError:
            raise Error.no_privileges(IOError, module)
    else:
        return False, "IPtables save doesn't exist."

def main():
    ''' Check if an iptables save already exists, update or create it if necessary '''
    
    fields = {
            "username": {"default": "", "type": "str"},
            "password": {"default": "", "no_log": True, "type": "str"},
            "host": {"default": "", "type": "str"},
            "INITD_PATH": {"default": "/etc/init.d/", "type": "str"},
            "SSH_PATH": {"default": "/root/.ssh/", "type": "str"},
            "REMOTE_PATH": {"default": "/LogsArchiving_REPO/", "type": "str"},
            "IPTABLES_PREFIX": {"default": "save_iptables_", "type": "str"},
            "RSA_FILE": {"default": "id_rsa_archiving", "type": "str"},
            "PUB_RSA_FILE": {"default": "id_rsa_archiving.pub", "type": "str"},
            "state": {
                "default": "present", 
                "choices": ['present', 'absent'],  
                "type": 'str' 
                }
            }

    choice_map = {
        "present": make_save,
        "absent": remove_save
        }

    module = AnsibleModule(argument_spec = fields)

    has_changed, result = choice_map.get(module.params['state'])(module)
    module.exit_json(changed=has_changed, msg=result)

############################################################################################################################################################
############################################################################################################################################################

if __name__ == '__main__':

    main()