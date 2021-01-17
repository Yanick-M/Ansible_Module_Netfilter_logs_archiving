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
module: daemon_script
short_description: Make Netfilter rules persistent
description:
    - Create a script base on a daemon template which is going to apply prefix to Netfilter log and restore an iptables save.
version_added: "3.7.3"
options:
    IPTABLES_RULES_LIST:
        description:
            - a list of the IPtables logs rules you want to add to Netfilter.
        needed: with present state
        example: COMING SOOOOOOOOOOOOOOOOOOOOOOOOOOOOON

    DAEMON_COMMANDS_LIST:
        description:
            - a list which contains the default template of the daemon.
        needed: with present state
        example: https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/persistent_firewall/vars/main.yml

    state:
        description:
            - Indicates if you want to create or remove daemon script file.
        default: present
        choices: {present, absent}

requirements:
    - an IPtables save made with the module iptables_save
    - a linux system working with systemd or sysV
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
- name: "create daemon script"
  hosts: All
  tasks:
    - name: "Use my module"
      daemon_script:
        state: "present"
        username: "{{username}}"
        password: "{{password}}"
        host: "{{host}}"
        IPTABLES_RULES_LIST: "{{IPTABLES_RULES_LIST}}"
        DAEMON_COMMANDS_LIST: "{{DAEMON_COMMANDS_LIST}}"

- name: "create daemon script without a copy on a remote machine"
  hosts: All
  tasks:
    - name: "Use my module"
      daemon_script:
        state: "present"
        IPTABLES_RULES_LIST: "{{IPTABLES_RULES_LIST}}"
        DAEMON_COMMANDS_LIST: "{{DAEMON_COMMANDS_LIST}}"

- name: "remove daemon script"
  hosts: All
  tasks:
    - name: "Use my module"
      daemon_script:
        state: "absent"

- name: "create daemon script with all vars defined"
  hosts: All
  tasks:
    - name: "Use my module"
      daemon_script:
        state: "present"
        username: "aic"
        password: "Azerty123&"
        host: "ServerCentral"
        IPTABLES_RULES_LIST: "[...]"
        DAEMON_COMMANDS_LIST: "[...]"
        INITD_PATH: "/etc/init.d/"
        SSH_PATH: "/root/.ssh/"
        REMOTE_PATH: "/LogsArchiving_REPO/"
        DAEMON_PREFIX: "firewall_"
        IPTABLES_PREFIX: "save_iptables_"
        RSA_FILE: "id_rsa_archiving"
        PUB_RSA_FILE: "id_rsa_archiving.pub"
        BLOC_A: "# Logs comments"
        BLOC_B: "# Restore IPtables rules"
'''
RETURN = '''
Nothing more than changed and a result message.
'''

import os, socket, stat, paramiko
from ansible.module_utils.basic import AnsibleModule
from scp import SCPClient

############################################################################################################################################################
############################################################################################################################################################

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

class daemon:
    ''' Class to manage a "Netfilter Daemon" '''

    def __init__(self, module):
        ''' Initialize the object '''
        
        self.name = module.params.get("DAEMON_PREFIX") + socket.gethostname() +".sh"
        self.path = module.params.get('INITD_PATH')
        self.remote_path = module.params.get('REMOTE_PATH') + socket.gethostname() + "/"
        self.save_name = module.params.get("IPTABLES_PREFIX") + socket.gethostname()
        self.logs_rules = module.params.get('IPTABLES_RULES_LIST')
        self.bloc_A = module.params.get('BLOC_A')
        self.bloc_B = module.params.get('BLOC_B')
        self._read(module)

    def _read(self, module):
        ''' Check if the daemon script exists on the remote host '''
        
        try:
            self.daemon_commands = read_file(self.path, self.name)
            self.existing = True
        except MyFileNotFound as exc:
            self.daemon_commands = module.params.get('DAEMON_COMMANDS_LIST')
            self.existing = False
        except ReadingFailure as esc:
            raise Error.privileges(ReadingFailure, module)
    
    def download(self, link, module):
        ''' Download a copy of a previous script creation on the remote host from the target machine '''

        link.download_file(self.path, self.remote_path, self.name, module)
        self._read(module)

    def upload(self, link, module):
        ''' Upload a copy of the script from the remote host to the target machine '''

        link.upload_file(self.path, self.remote_path, self.name, module)

    def _compare_logs_rules(self, module):
        ''' Check if desired iptables logs rules are already configured and save in a list which are not '''

        try:
            tables = read_file(self.path, self.save_name)
        except MyFileNotFound as exc:
            raise Error.file_missing(MyFileNotFound, self.path, self.save_name, module)
        all_rules = self.daemon_commands + tables
        self.rules_to_define = []
        
        for rule in self.logs_rules:
            rule_found = False
            for command in all_rules:
                if rule == command or rule[9:] == command:
                    rule_found = True
                    break
            if rule_found is False:
                self.rules_to_define.append(rule)
        
        if not self.rules_to_define:
            raise EmptySearch

    def _find_bloc(self, bloc):
        ''' Check for the line number of a commentary in the script content '''
        
        position = 0
        
        for command in self.daemon_commands:
        
            if command == bloc:
                break
            position += 1
        
        if position == len(self.daemon_commands):
            raise EmptySearch

        return(position)

    def update_script(self, link, module):
        ''' Rewrite the script with the new logs rules '''
            
        try:
            self._compare_logs_rules(module)
            try:
                self.bloc_A_position = self._find_bloc(self.bloc_A) + 1
            except EmptySearch as exc:
                raise Error.fatal_error(EmptySearch, module)
            self._update_commands(self.bloc_A_position, self.rules_to_define)
            self.write_commands(link, module)
        except EmptySearch as exc:
            raise NoUpDateNeeded

    def _update_commands(self, bloc_position, data):
        ''' Insert new logs rules commands in the content of the existing script '''
        
        for rule in reversed(self.rules_to_define):
            self.daemon_commands.insert(bloc_position, rule)

    def write_commands(self, link, module):
        ''' Write the content in a file on the remote host '''

        try:
            write_file(self.path, self.name, self.daemon_commands)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure, module)
        
        self.implement(module)
        self.upload(link, module)
    
    def implement(self, module):
        ''' Change the permission of the script, declare and start the service '''

        rights = stat.S_IRWXU
        try:
            implement_file(self.path, self.name, rights)
        except MyFileNotFound as exc:
            raise Error.erreurfatale(MyFileNotFound, module)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure, module)

        #os.system('update-rc.d "{}" defaults > /dev/null 2>&1'.format(self.name))
        #os.system('"{}./{}" start'.format(self.path, self.name))
        os.system('ln -s "{}{}" "/etc/systemd/system/multi-user.target.wants/{}service"'.format(self.path, self.name, self.name[:-2]))
        os.system('systemctl enable {} > /dev/null 2>&1'.format(self.name))
        result = os.system('systemctl start {}service > /dev/null 2>&1'.format(self.name[:-2]))
        if result == 1280:
            module.warn("Unable to start daemon !")
    
    def create_commands(self, module):
        ''' Create the content of the script '''
        
        try:
            self._compare_logs_rules(module)
        except EmptySearch as exc:
            raise Error.fatal_error(EmptySearch, module)
        
        try:
            self.bloc_A_position = self._find_bloc(self.bloc_A) + 1
        except EmptySearch as exc:
            raise Error.fatal_error(EmptySearch, module)
        
        self._update_commands(self.bloc_A_position, self.rules_to_define)

        try:
            self.bloc_B_position = self._find_bloc(self.bloc_B) + 1
        except EmptySearch as exc:
            raise Error.fatal_error(EmptySearch, module)

        self.daemon_commands.insert(self.bloc_B_position, "iptables-restore -n < \"{}{}\"".format(self.path, self.save_name))

############################################################################################################################################################
############################################################################################################################################################

def make_script(module):
    
    # Objects establishing for the daemon and the ssh connection
    job = daemon(module)
    link = ssh(module)

    # If a script has been found in init.d directory, trying to see if the desired logs rules exists
    # No, the script is updated
    # Yes, the module is quit
    if not (job.logs_rules and job.daemon_commands):
        raise Error.empty_list(job.logs_rules, module)
    elif job.existing is True:
        try:
            job.update_script(link, module)
            msg = "Daemon has been updated with new logs rules."
            return True, msg
        except NoUpDateNeeded as exc:
            msg = "Nelfilter daemon already exits."
            return False, msg
    # If not, trying to download it from remote server then updating if needed
    # If no save on the remote server, the script is generated      
    else:
        job.download(link, module)
        if job.existing is True:
            try:
                job.update_script(link, module)
                msg = "Daemon has been downloaded and updated with new logs rules."
                return True, msg
            except NoUpDateNeeded as exc:
                job.implement(module)
                msg = "Up to date netfilter daemon has been downloaded from remote server."
                return True, msg
        else:
            job.create_commands(module)
            job.write_commands(link, module)
            msg = "Daemon has been created with desired logs rules."
            return True, msg

def erase_script(module):
    
    job = daemon(module)
    if job.existing is True:
        try:
            os.remove(job.path + job.name)
            msg = "Netfilter daemon script has been removed."
            return True, msg
        except IOError:
            raise Error.no_privileges(IOError, module)   
    else:
        msg = "Netfilter daemon script has not been found."
        return False, msg


def main():
    ''' Check if the daemon script already exists, update or create it if necessary '''
    
    fields = {
            "username": {"default": "", "type": "str"},
            "password": {"default": "", "no_log": True, "type": "str"},
            "host": {"default": "", "type": "str"},
            "IPTABLES_RULES_LIST": {"default": [], "type": "list"},
            "DAEMON_COMMANDS_LIST": {"default": [], "type": "list"},
            "INITD_PATH": {"default": "/etc/init.d/", "type": "str"},
            "SSH_PATH": {"default": "/root/.ssh/", "type": "str"},
            "REMOTE_PATH": {"default": "/LogsArchiving_REPO/", "type": "str"},
            "DAEMON_PREFIX": {"default": "firewall_", "type": "str"},
            "IPTABLES_PREFIX": {"default": "save_iptables_", "type": "str"},
            "RSA_FILE": {"default": "id_rsa_archiving", "type": "str"},
            "PUB_RSA_FILE": {"default": "id_rsa_archiving.pub", "type": "str"},
            "BLOC_A": {"default": "# Logs comments", "type": "str"},
            "BLOC_B": {"default": "# Restore IPtables rules", "type": "str"},
            "state": {
                "default": "present", 
                "choices": ['present', 'absent'],  
                "type": 'str' 
                }
            }

    choice_map = {
        "present": make_script,
        "absent": erase_script
        }

    module = AnsibleModule(argument_spec = fields)

    has_changed, result = choice_map.get(module.params['state'])(module)
    module.exit_json(changed=has_changed, msg=result)

############################################################################################################################################################
############################################################################################################################################################

if __name__ == '__main__':

    main()