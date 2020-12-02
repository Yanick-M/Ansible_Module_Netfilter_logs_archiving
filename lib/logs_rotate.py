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

class logrotate:
    ''' Class to manage Netfilter logs rotation '''
    
    def __init__(self):
        ''' Initialize the object '''

        self.name = module.params.get('LOGROTATE_FILE_NAME')
        self.path = module.params.get('LOGROTATE_PATH')
        self.list = module.params.get('LOGROTATE_LIST')
        self._read()

    def _read(self):
        ''' Check if logrotate conf file exists for Netfilter logs '''

        try:
            read_file(self.rotate_path, self.rotate_name)
            self.existing = True
        except MyFileNotFound as exc:
            self.existing = False
        except ReadingFailure as exc:
            raise Error.no_privileges(ReadingFailure)

    def create_logs_rotation(self):
        ''' Create logrotate conf file '''

        try:
            write_file(self.rotate_path, self.rotate_name, self.rotate_list)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure, self.rotate_path, self.rotate_name)

############################################################################################################################################################
############################################################################################################################################################

def main():
    ''' Check if a logrotate conf file exists for netfilter logs, create or remove it if necessary '''

    module = AnsibleModule(
        argument_spec = dict(
            state = dict(required = True, choices = ['present', 'absent']),
            LOGROTATE_FILE_NAME = dict(required = True, type = 'str'),
            LOGROTATE_PATH = dict(required = True, type = 'str'),
            LOGROTATE_LIST = dict(required = True, type = 'list')
        )
    )

    state = module.params.get('state')

    rotate = logrotate()

    if state.lower() == "absent":
        if rotate.existing is True:
            try:
                os.remove(rotate.path, rotate.name)
                module.exit_json(changed = True, msg = "Logrotate conf file has been removed.")
            except IOError:
                raise Error.no_privileges(IOError)
        else:
            module.exit_json(changed = False, msg = "Logrotate conf file has not been removed.")

    elif state.lower() == "present":
        if rotate.existing is True:
            module.exit_json(changed = False, msg = "Logrotate conf file already exists.")
        else:
            rotate.create_logs_rotation()
            module.exit_json(changed = True, msg = "Logrotate conf file has been created.")
    
    else:
        raise Error.state_argument_error(state)

############################################################################################################################################################
############################################################################################################################################################

if __name__ == '__main__':

    main()