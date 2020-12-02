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
    ''' To change file permissions '''

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

class task:
    ''' Class to manage crontab task '''

    def __init__(self):
        ''' Initialize the object '''
        
        self.name = module.params.get('CRONTAB_FILE_NAME')
        self.path = module.params.get('CRONTAB_PATH')
        self.script_name = module.params.get('ARCHIVING_SCRIPT_NAME')
        self.script_path = module.params.get('ARCHIVING_SCRIPT_PATH')
        self._read()

    def _read(self):
        ''' Check if a crontab file exists '''

        try:
            self.file_content = read_file(self.path, self.name)
            self.existing_file = True
        except MyFileNotFound as exc:
            self.existing_file = False
        except ReadingFailure as exc:
            raise Error.privileges(ReadingFailure)

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

        # Ajout de la tâche à l'aide d'une commande bash dans le fichier root du répertoire crontabs
        os.system("echo '0 7 * * *  \"{}./{}\"' >> \"{}{}\"".format(self.script_path, self.script_name, self.path, self.name))
        
        # Activation de la tâche à l'aide d'une commande bash (le fichier sera ainsi lisible et modifiable par root ou le groupe crontab uniquement)
        os.system("crontab \"{}{}\"".format(self.path, self.name))

############################################################################################################################################################
############################################################################################################################################################

def main():
    ''' Check if the root crontab file already exists, update or create it if necessary '''

    module = AnsibleModule(
        argument_spec = dict(
            state = dict(required = True, choices = ['present', 'absent']),
            CRONTAB_PATH = dict(required = True, type = 'str'),
            CRONTAB_FILE_NAME = dict(required = True, type = 'str'),
            ARCHIVING_SCRIPT_PATH = dict(required = True, type = 'str'),
            ARCHIVING_SCRIPT_NAME = dict(required = True, type = 'str'),
        )
    )

    state = module.params.get('state')

    # Object establishing for the crontab task
    crontab = task()

    if state.lower() == "absent":
        if crontab.existing_file is True:
            try:
                os.system("sed -i\".bak\" '/{}/d' \"{}{}\"".format(crontab.script_name, crontab.path, crontab.name))
                module.exit_json(changed = True, msg = "Archiving task has been removed.")
            except IOError:
                raise Error.no_privileges(IOError)
        module.exit_json(changed = False, msg = "root don't have a specific crontab file.")

    elif state.lower() == "present":
        # If the root crontab file exists, checking if the desired task is configured
        # Yes, no change needed
        # No, updating the file
        if crontab.existing_file is True:
            try:
                crontab.search(crontab.script_name)
                module.exit_json(changed = False, msg = "The archiving task already exists.")
            except EmptySearch as exc:
                crontab.create_task()
        # If not, creating file
        else:
            crontab.create_task()

    else:
        raise Error.state_argument_error(state)

if __name__ == '__main__':

    main()