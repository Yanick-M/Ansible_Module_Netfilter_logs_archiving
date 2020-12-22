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
module: own_logs
short_description: Create rsyslog conf file for Netfilter logs
description:
    - Create a rsyslog conf file based on the IPtables rules list who defined which Netfilter logs you want to be tagged with a prefix,
    - Tagged logs will be redirect in specific files in "/var/log/netfilter/".
version_added: "3.7.3"
options:
    IPTABLES_RULES_LIST:
        description:
            - a list of the IPtables logs rules you want to add to Netfilter.
        needed: with present state
        example: COMING SOOOOOOOOOOOOOOOOOOOOOOOOOOOOON

    state:
        description:
            - Indicates if you want to create or remove rsyslog conf file.
        default: present
        choices: {present, absent}
requirements:
    - rsyslog
author: "Yanick-M"
notes:
    - THIS MODULE REQUIRES PRIVILEGES !!!
'''

EXAMPLES = '''
- name: "configure rsyslog for Netfilter own logs"
  hosts: All
  tasks:
    - name: "Use my module"
      own_logs:
        state: "present"
        IPTABLES_RULES_LIST: "{{IPTABLES_RULES_LIST}}"

- name: "remove rsyslog conf file for Netfilter own logs"
  hosts: All
  tasks:
    - name: "Use my module"
      own_logs:
        state: "absent"

- name: "configure rsyslog for Netfilter own logs with all vars defined"
  hosts: All
  tasks:
    - name: "Use my module"
      daemon_script:
        state: "present"
        IPTABLES_RULES_LIST: "[...]"
        RSYSLOG_PATH: "/etc/rsyslog.d/"
        LOGS_PATH: "/var/log/netfilter/"
        RSYSLOG_CONF_FILE: "10-iptables.conf"
        
'''
RETURN = '''
Nothing more than changed and a result message.
'''

import os
from ansible.module_utils.basic import AnsibleModule

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
    ''' To change file permissions on the remote host '''

    try:
        os.chmod(path + name, rights)
    except FileNotFoundError:
        raise MyFileNotFound
    except PermissionError:
        raise WritingFailure

############################################################################################################################################################
############################################################################################################################################################

class logs:
    ''' Class to manage Netfilter own logs '''

    def __init__(self, module):
        ''' Initialize the object '''

        self.name = module.params.get('RSYSLOG_CONF_FILE')
        self.path = module.params.get('RSYSLOG_PATH')
        self.logs_path = module.params.get('LOGS_PATH')
        self.logs_rules = module.params.get('IPTABLES_RULES_LIST')
        self._read(module)

    def _read(self, module):
        ''' Check if an iptables conf file for rsyslog exists '''  
        
        try:
            self.rsyslog_commands = read_file(self.path, self.name)
            self.existing = True
        except MyFileNotFound as exc:
            self.existing = False
        except ReadingFailure as esc:
            raise Error.privileges(ReadingFailure, module)
    
    def compare_rsyslog_commands(self):
        ''' Check in the content of the rsyslog conf file if the logs prefix exist '''

        self.commands_to_define = []

        for rule in self.logs_rules:
            
            command_find = False

            if not self.rsyslog_commands:
                self.commands_to_define.append(rule[rule.find("\""):rule.rfind("\"") + 1])
            else:                                                                             
                for command in self.rsyslog_commands:
                    if rule[rule.find("\""):rule.rfind("\"") + 1] == command[command.find("\""):command.rfind("\"") + 1]:
                        command_find = True
                        break
                if command_find is False:
                    self.commands_to_define.append(rule[rule.find("\""):rule.rfind("\"") + 1])

        if not self.commands_to_define:
            raise EmptySearch
    
    def _update_commands(self):
        ''' Update the content of the rsyslog conf file with new commands '''
        
        for rule in self.commands_to_define:
            self.rsyslog_commands.append(":msg, contains, {} -/var/log/netfilter/{}.log \n & ~".format(rule, rule[1:-3]))

    def write_commands(self, module):
        ''' Write the content in a file on the remote host '''

        try:
            write_file(self.path, self.name, self.rsyslog_commands)
            self.create_directory(module)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure,self.path, self.name, module)

    def update_conf_file(self, module):
        ''' Rewrite the conf file with the update content '''

        self._update_commands()
        self.write_commands(module)

    def create_directory(self, module):
        ''' Create a directory to store Netfilter logs '''

        try:
            os.makedirs(self.logs_path)
            os.system("chown root:syslog {0} && chmod 755 {0}".format(self.logs_path))
        except FileExistsError as exc:
            pass
        except IOError as exc:
            raise Error.no_privileges(IOError, module)

    def create_conf_file(self, module):
        ''' Generate the content of the rsyslog conf file '''

        self.rsyslog_commands = []
        try:
            self.compare_rsyslog_commands()
        except EmptySearch as exc:
            raise Error.fatal_error(EmptySearch, module)

        self._update_commands()

############################################################################################################################################################
############################################################################################################################################################

def make_conf_file(module):
    
    # Object establishing for the Netfilter logs
    job = logs(module)
    
    # If a rsyslog conf file exits, trying to see if the desired logs rules exists
    # No, rsyslog conf file is updated and logrotate check
    # Yes, just check logrotate
    if not job.logs_rules:
        raise Error.empty_list(job.logs_rules, module)
    elif job.existing is True:
        try:
            job.compare_rsyslog_commands()
            job.update_conf_file(module)
            msg = "Rsyslog conf file has been updated with new Netfilter logs."
            return True, msg
        except EmptySearch as exc:
            msg = "Netfilter has already his own logs."
            return False, msg
    # If not, create the conf files for rsyslog and logrotate
    else:
        job.create_conf_file(module)
        job.write_commands(module)
        msg = "Rsyslog conf file has been created, Nefilter has is own logs"
        return True, msg
    

def erase_conf_file(module):
    
    # Object establishing for the Netfilter logs
    job = logs(module)
    if job.existing is True:
        try:
            os.remove(job.path + job.name)
            msg = "Netfilter logs configuration has been removed."
            return True, msg
        except IOError:
            raise Error.no_privileges(WritingFailure)
    else:
        msg = "Nelfilter logs configuration has not been found."
        return False, msg

def main():
    ''' Check if the rsyslog conf file already exists, update, create or remove it if necessary '''

    fields = {
            "IPTABLES_RULES_LIST": {"default": [], "type": "list"},
            "RSYSLOG_PATH": {"default": "/etc/rsyslog.d/", "type": "str"},
            "LOGS_PATH": {"default": "/var/log/netfilter/", "type": "str"},
            "RSYSLOG_CONF_FILE": {"default": "10-iptables.conf", "type": "str"},
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