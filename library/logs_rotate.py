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
module: logs_rotate
short_description: Create logrotate conf file for Netfilter logs files
description:
    - Create a logrotate conf file to established a daily rotation on Netfilter own logs files.
version_added: "3.7.3"
options:
    LOGROTATE_LIST:
        description:
            - a list of a basic conf file template.
        needed: with present state
        example: https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/firewall_logs/vars/main.yml

    state:
        description:
            - Indicates if you want to create or remove rsyslog conf file.
        default: present
        choices: {present, absent}
requirements:
    - logrotate
author: "Yanick-M"
notes:
    - THIS MODULE REQUIRES PRIVILEGES !!!
'''

EXAMPLES = '''
- name: "configure logrotate for Netfilter logs files"
  hosts: All
  tasks:
    - name: "Use my module"
      logs_rotate:
        state: "present"
        LOGROTATE_LIST: "{{LOGROTATE_LIST}}"

- name: "remove logrotate conf file for Netfilter logs files"
  hosts: All
  tasks:
    - name: "Use my module"
      logs_rotate:
        state: "absent"

- name: "configure logrotate for Netfilter logs files with all vars defined"
  hosts: All
  tasks:
    - name: "Use my module"
      daemon_script:
        state: "present"
        LOGROTATE_LIST: "[...]"
        LOGROTATE_FILE_NAME: "netfilter.conf"
        LOGROTATE_PATH: "/etc/logrotate.d/"        
'''
RETURN = '''
Nothing more than changed and a result message.
'''

import os
from ansible.module_utils.basic import AnsibleModule

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
    ''' To change file permissions on the remote host '''

    try:
        os.chmod(path + name, rights)
    except FileNotFoundError:
        raise MyFileNotFound
    except PermissionError:
        raise WritingFailure

############################################################################################################################################################
############################################################################################################################################################

class logrotate:
    ''' Class to manage Netfilter logs rotation '''
    
    def __init__(self, module):
        ''' Initialize the object '''

        self.name = module.params.get('LOGROTATE_FILE_NAME')
        self.path = module.params.get('LOGROTATE_PATH')
        self.list = module.params.get('LOGROTATE_LIST')
        self._read(module)

    def _read(self, module):
        ''' Check if logrotate conf file exists for Netfilter logs '''

        try:
            read_file(self.path, self.name)
            self.existing = True
        except MyFileNotFound as exc:
            self.existing = False
        except ReadingFailure as exc:
            raise Error.no_privileges(ReadingFailure, module)

    def create_logs_rotation(self, module):
        ''' Create logrotate conf file '''

        try:
            write_file(self.path, self.name, self.list)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure, self.rotate_path, self.rotate_name, module)

############################################################################################################################################################
############################################################################################################################################################

def make_conf_file(module):

    # Object establishing for the Netfilter logs rotation
    job = logrotate(module)
    if not job.list:
        raise Error.empty_list(job.list, module)
    else:
        if job.existing is True:
            return False, "La liste est : {}".format(job.list) #"Logrotate conf file already exists."
        else:
            job.create_logs_rotation(module)
            return True, "Logrotate conf file has been created."

def erase_conf_file(module):
    
    # Object establishing for the Netfilter logs rotation
    job = logrotate(module)

    if job.existing is True:
        try:
            os.remove(job.path + job.name)
            return True, "Logrotate conf file has been removed."
        except IOError:
            raise Error.no_privileges(IOError, module)
    else:
        return False, "Logrotate conf file has not been removed."

def main():
    ''' Check if a logrotate conf file exists for netfilter logs, create or remove it if necessary '''

    fields = {
            "LOGROTATE_FILE_NAME": {"default": "netfilter.conf", "type": "str"},
            "LOGROTATE_PATH": {"default": "/etc/logrotate.d/", "type": "str"},
            "LOGROTATE_LIST": {"default": [], "type": "list"},
            "state": {
                "default": "present", 
                "choices": ['present', 'absent'],  
                "type": 'str' 
                }
            }

    choice_map = {
        "present": make_conf_file,
        "absent": erase_conf_file
        }

    module = AnsibleModule(argument_spec = fields)

    has_changed, result = choice_map.get(module.params['state'])(module)
    module.exit_json(changed=has_changed, msg=result)

############################################################################################################################################################
############################################################################################################################################################

if __name__ == '__main__':

    main()