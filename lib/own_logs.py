#! /usr/bin/env python3
# coding: utf-8

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
Le répertoire servant de dépôt pour les fichiers doit être créé au préalable et appartenir à l'utilisateur appelés en argument
Le module paramiko doit être présent sur le système ---> A traduire
'''
EXAMPLES = r'''
'''
RETURN = r'''
'''

import os, socket, stat, paramiko
from ansible.module_utils.basic import AnsibleModule
from scp import SCPClient

# Define module user-defined exceptions and errors
class Error(Exception):
    ''' Base class for errors that require to stop module execution '''

    def no_privileges(self):
        ''' raised when an action need privileges '''
        module.exit_json(changed = False, msg = "\033[31mMust be run as root !\033[0m")

    def file_missing(self, path, name):
        ''' raised when a file does not exists on the remote host '''
        module.exit_json(changed = False, msg = "\033[31mThe file {} in \"{}\" is missing !\033[0m".format(path, name))

    def unable_to_write(self, path, name):
        ''' raised when a file can't be created or modified on the remote host '''
        module.exit_json(changed = False, msg = "\033[31m Can't write the file {} in \"{}\" !\033[0m".format(path, name))

    def fatal_error(self):
        ''' raised when a unknown problem occurs '''
        module.exit_json(changed = False, msg = "\033[31mFatal error, report bug !\033[0m")
    
    def state_argument_error(self):
        ''' raised when a state argument problem occurs '''
        module.exit_json(changed = False, msg = "\033[31mState argument only accept 'present' or 'absent' !\033[0m")

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

    print("-----reading file {} in \"{}\"-----".format(name, path))
    try:
        my_file = open(path + name, "r")
        liste = [i[:-1] for i in my_file]
        my_file.close()
        print("\033[32m-----the file has been found and read-----\033[0m")
    except FileNotFoundError:
        raise MyFileNotFound
    except IOError:
        raise ReadingFailure
    
    return(liste)

def write_file(path, name, data):
    ''' To write data in a file on the remote host '''

    print("-----saving data in the file {} in \"{}\"-----".format(name, path))
    try:
        with open(path + name, "w") as fichier:
            for line in data:
                fichier.write("{}\n".format(line))
        print("\033[32m-----the file has been created or modified-----\033[0m")
    except IOError:
        raise WritingFailure

def implement_file(path, name, rights):
    ''' To change file permissions on the remote host '''

    print("-----changing permissions of {} in \"{}\"-----".format(name, path))
    try:
        os.chmod(path + name, rights)
        print("\033[32m-----the permissions are changed-----\033[0m")
    except FileNotFoundError:
        raise MyFileNotFound
    except PermissionError:
        raise WritingFailure

############################################################################################################################################################
############################################################################################################################################################

class logs:
    ''' Class to manage Netfilter own logs '''

    def __init__(self):
        ''' Initialize the object '''

        self.name = module.params.get('RSYSLOG_CONF_FILE')
        self.path = module.params.get('RSYSLOG_PATH')
        self.logs_path = module.params.get('LOGS_PATH')
        self.logs_rules = module.params.get('IPTABLES_RULES_LIST')
        self._read()

    def _read(self):
        ''' Check if an iptables conf file for rsyslog exists '''  
        
        try:
            self.rsyslog_commands = read_file(self.path, self.name)
            self.existing = True
        except MyFileNotFound as exc:
            self.existing = False
        except ReadingFailure as esc:
            raise Error.privileges(ReadingFailure)
    
    def compare_rsyslog_commands(self):
        ''' Check in the content of the rsyslog conf file if the logs prefix exist '''

        self.commands_to_define = []

        print("-----data comparison-----")
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

    def write_commands(self):
        ''' Write the content in a file on the remote host '''

        try:
            write_file(self.path, self.name, self.rsyslog_commands)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure)

    def update_conf_file(self):
        ''' Rewrite the conf file with the update content '''

        self._update_commands()
        self.write_commands()

    def create_directory(self):
        ''' Create a directory to store Netfilter logs '''

        print("\n\033[36mChecking for Netfilter logs directory...\033[0m")
        try:
            os.makedirs(self.logs_path)
            os.system("chown root:syslog {0} && chmod 775 {0}".format(self.logs_path))
        except FileExistsError as exc:
            pass
        except IOError as exc:
            raise Error.no_privileges(IOError)

    def create_conf_file(self):
        ''' Generate the content of the rsyslog conf file '''

        self.rsyslog_commands = []
        try:
            self.compare_rsyslog_commands()
        except EmptySearch as exc:
            raise Error.fatal_error(EmptySearch)

        self._update_commands()

############################################################################################################################################################
############################################################################################################################################################

def main():
    ''' Check if the rsyslog conf file already exists, update, create or remove it if necessary '''

    module = AnsibleModule(
        argument_spec = dict(
            state = dict(required = True, choices = ['present', 'absent']),
            RSYSLOG_PATH = dict(required = True, type = 'str'),
            LOGS_PATH = dict(required = True, type = 'str'),
            RSYSLOG_CONF_FILE = dict(required = True, type = 'str'),
            IPTABLES_RULES_LIST = dict(required = True, type = 'list'),
        )
    )

    state = module.params.get('state')

    # Object establishing for the Netfilter logs
    iptables_logs = logs()

    if state.lower() == "absent":
        if iptables_logs.existing is True:
            try:
                os.remove()(iptables_logs.path, iptables_logs.name)
                module.exit_json(changed = True, msg = "Netfilter logs configuration has been removed.")
            except IOError:
                raise Error.no_privileges(WritingFailure)
        else:
            module.exit_json(changed = False, msg = "Nelfilter logs configuration has not been found.")
    
    elif state.lower() == 'present':
        # If a rsyslog conf file exits, trying to see if the desired logs rules exists
        # No, rsyslog conf file is updated and logrotate check
        # Yes, just check logrotate
        if iptables_logs.existing is True:
            try:
                iptables_logs.compare_rsyslog_commands()
                iptables_logs.update_conf_file()
                module.exit_json(changed = True, msg = "Rsyslog conf file has been updated with new Netfilter logs.")
            except EmptySearch as exc:
                module.exit_json(changed = False, msg = "Netfilter has already his own logs.")
        # If not, create the conf files for rsyslog and logrotate
        else:
            iptables_logs.create_conf_file()
            iptables_logs.write_commands()
            module.exit_json(changed = True, msg = "Rsyslog conf file has been created, Nefilter has is own logs")
    
    else:
        raise Error.state_argument_error(state)

############################################################################################################################################################
############################################################################################################################################################

if __name__ == '__main__':

    main()