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
module: archiving_task
short_description: Create a cron task for Netfilter logs archiving
description:
    - Create a cron task which is going to execute an archiving script in "/root/" every day at 7:00 AM just after logrotate task.
version_added: "3.7.3"
options:
    state:
        description:
            - Indicates if you want to create or remove rsyslog conf file.
        default: present
        choices: {present, absent}
requirements:
    - cron
author: "Yanick-M"
notes:
    - THIS MODULE REQUIRES PRIVILEGES !!!
'''

EXAMPLES = '''
- name: "configure a cron task to execute archiving script"
  hosts: All
  tasks:
    - name: "Use my module"
      archiving_task:
        state: "present"
        LOGROTATE_LIST: "{{LOGROTATE_LIST}}"

- name: "remove the cron task which execute the archiving script"
  hosts: All
  tasks:
    - name: "Use my module"
      archiving_task:
        state: "absent"

- name: "configure logrotate for Netfilter logs files with all vars defined"
  hosts: All
  tasks:
    - name: "Use my module"
      archiving_task:
        state: "present"
        CRONTAB_PATH: "/var/spool/cron/crontabs/"
        CRONTAB_FILE_NAME: "root",
        ARCHIVING_SCRIPT_PATH: "/root/"
        ARCHIVING_SCRIPT_NAME: "netfilter_logs_archiving.sh"        
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

class task:
    ''' Class to manage crontab task '''

    def __init__(self, module):
        ''' Initialize the object '''
        
        self.name = module.params.get('CRONTAB_FILE_NAME')
        self.path = module.params.get('CRONTAB_PATH')
        self.script_name = module.params.get('ARCHIVING_SCRIPT_NAME')
        self.script_path = module.params.get('ARCHIVING_SCRIPT_PATH')
        self._read(module)

    def _read(self, module):
        ''' Check if a crontab file exists '''

        try:
            self.file_content = read_file(self.path, self.name)
            self.existing_file = True
        except MyFileNotFound as exc:
            self.existing_file = False
        except ReadingFailure as exc:
            raise Error.privileges(ReadingFailure, module)

    def search(self, value):
        ''' Check if a value exists in the content of the crontab file'''

        result = False
        for line in self.file_content:
            if line.find(value) >= 0:
                result = True
        if result is False:
            raise EmptySearch
    
    def create_task(self):
        ''' Create the archiving task in the crontab file and activate the crontab '''

        os.system("echo '0 7 * * *  \"{}./{}\"' >> \"{}{}\"".format(self.script_path, self.script_name, self.path, self.name))
        
        os.system("crontab \"{}{}\"".format(self.path, self.name))

############################################################################################################################################################
############################################################################################################################################################

def configure_crontab(module):
    
    # Object establishing for the crontab task
    job = task(module)

    # If the root crontab file exists, checking if the desired task is configured
    # Yes, no change needed
    # No, updating the file
    if job.existing_file is True:
        try:
            job.search(job.script_name)
            return False, "The archiving task already exists."
        except EmptySearch as exc:
            job.create_task()
            return True, "An archiving task has been added for root."
    # If not, creating file
    else:
        job.create_task()
        return True, "A root crontab and the archiving task have been created."


def remove_task(module):

    # Object establishing for the crontab task
    job = task(module)

    if job.existing_file is True:
        try:
            os.system("sed -i\".bak\" '/{}/d' \"{}{}\"".format(job.script_name, job.path, job.name))
            return True, "Archiving task has been removed."
        except IOError:
            raise Error.no_privileges(IOError, module)
    else:
        return False, "root don't have a specific crontab file."

def main():
    ''' Check if the root crontab file already exists, update or create it if necessary '''

    fields = {
            "CRONTAB_PATH": {"default": "/var/spool/cron/crontabs/", "type": "str"},
            "CRONTAB_FILE_NAME": {"default": "root", "type": "str"},
            "ARCHIVING_SCRIPT_PATH": {"default": "/root/", "type": "str"},
            "ARCHIVING_SCRIPT_NAME": {"default": "netfilter_logs_archiving.sh", "type": "str"},
            "state": {
                "default": "present", 
                "choices": ['present', 'absent'],  
                "type": 'str' 
                }
            }

    module = AnsibleModule(argument_spec = fields)

    choice_map = {
        "present": configure_crontab,
        "absent": remove_task
        }

    module = AnsibleModule(argument_spec = fields)

    has_changed, result = choice_map.get(module.params['state'])(module)
    module.exit_json(changed=has_changed, msg=result)

if __name__ == '__main__':

    main()