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

class ssh:
    ''' Class for ssh operations '''

    def __init__(self, username, password, host):
        ''' Initialize the object '''

        self.host = host
        self.client = None
        self.scp = None
        self.username = username
        self.password = password
        self._connect()

    def _connect(self):
        ''' Initialize the connection '''
        
        try:
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._check_rsa_keys()
            self.client.connect(self.host, username = self.username, pkey = self.ssh_key)
            self.scp = SCPClient(self.client.get_transport())
        except:
            pass
        finally:
            return self.client
    
    def _check_rsa_keys(self):
        ''' Check if rsa keys exist on the remote host (needed for ssh operations with no password input) '''

        self.rsa_key = module.params.get('RSA_FILE')
        self.pub_rsa_key = module.params.get('PUB_RSA_FILE')
        self.path_rsa_keys = module.params.get('SSH_PATH')
        try:
            read_file(self.path_rsa_keys, self.rsa_key)
            read_file(self.path_rsa_keys, self.pub_rsa_key)
            self.ssh_key = paramiko.RSAKey.from_private_key_file("{}{}".format(self.path_rsa_keys, self.rsa_key))
        except MyFileNotFound as exc:
            self._create_rsa_keys()
        except ReadingFailure as exc:
            raise Error.no_privileges(ReadingFailure)

    def _create_rsa_keys(self):
        ''' Create rsa keys on the remote host and copy the id on the target machine '''

        print("-----creating rsa keys-----")
        self.rights = stat.S_IREAD|stat.S_IWRITE

        os.system("rm \"{0}{1}\" > /dev/null 2>&1 | ssh-keygen -b 4096 -m PEM -f \"{0}{1}\" -N \"\" > /dev/null 2>&1".format(self.path_rsa_keys, self.rsa_key))

        try:
            implement_file(self.path_rsa_keys, self.rsa_key, self.rights)
            implement_file(self.path_rsa_keys, self.pub_rsa_key, self.rights)
        except FileNotFoundError as exc:
            pass
        except WritingFailure as exc:
            raise Error.no_privileges(IOError)

        result = os.system("sshpass -p \"{}\" ssh-copy-id -o StrictHostKeyChecking=no -i \"{}{}\" {}@{} > /dev/null 2>&1".format(self.password, self.path_rsa_keys, self.rsa_key, self.username, self.host))
        if result == 256:
            print("\033[31mUnable to tranfer id on {}, problem to study ! Maybe the name of the target machine or the name of the key are incorrect\033[0m".format(host.upper()))
        elif result == 1536:
            print("\033[31m The username of the target machine or his password on {} are incorrect !\033[0m".format(host.upper()))

        self.ssh_key = paramiko.RSAKey.from_private_key_file("{}{}".format(self.path_rsa_keys, self.rsa_key))

        print("\033[32m-----the rsa keys has been generated-----\033[0m")

    def disconnect(self):
        ''' Close the ssh connection with the target machine '''
        
        self.client.close()
        self.scp.close()

    def exec_command(self,command):
        ''' Execute a specified command on the target machine '''

        if self.client is None:
            self.client == self.__connect()
        stdin,stdout,stderr = self.client.exec_command(command)
        status = stdout.channel.recv_exit_status()
        if status == 0:
            return stdout.read()
        else:
            return None

    def download_file(self, path, remote_path, name):
        ''' Download a file from the target machine '''
    
        try:
            if self.client is None:
                self.client = self.__connect()
            self.scp.get('{}{}'.format(remote_path, name), '{}'.format(path))
            print("\033[32m-----the file {} has been downloaded from {}-----\033[0m".format(name, self.host.upper()))
        except:
            print("\033[33m-----Unable to download the file {} from {}-----\033[0m".format(name, self.host.upper()))

    def upload_file(self, path, remote_path, name):
        ''' Transfer a file on the target machine (create directories if they don't exists but not possible on root) '''

        try:
            if self.client is None:
                self.client = self.__connect()
            command = "mkdir -p {}".format(remote_path)
            self.exec_command("mkdir -p {}".format(remote_path))
            self.scp.put('{}{}'.format(path, name), '{}{}'.format(remote_path, name))
            print("\033[32m-----The file {} has been uploaded on {}-----\033[0m".format(name, self.host.upper()))
        except:
            print("\033[33m-----Unable to upload the file {} on {}-----\033[0m".format(name, self.host.upper()))

############################################################################################################################################################
############################################################################################################################################################

class archives:
    ''' Class to manage archiving script '''

    def __init__(self):
        ''' Initialize the object '''
        
        self.name = module.params.get('ARCHIVING_SCRIPT_NAME')
        self.path = module.params.get('ARCHIVING_SCRIPT_PATH')
        self._read()

    def _read(self):
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

        # Recherche d'une valeur dans chaque ligne d'une liste (ex. : le nom du script dans la tâche cronatb active)
        # Si la valeur n'est pas trouvée, une exception est levée
        result = False
        for line in self.file_content:
            if line.find(value) >= 0:
                result = True
        if result is False:
            raise EmptySearch

    def create_commands(self, host, username):
        ''' Create the content of the script '''

        self.commands = module.params.get('ARCHIVING_COMMANDS_LIST')

        self.commands.insert(2, "host={}".format(host))
        self.commands.insert(2, "user={}".format(username))

    def write_commands(self):
        ''' Write the content in a file on the remote host '''

        try:
            write_file(self.path, self.name, self.commands)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure)

        self.implement()

    def implement(self):
        ''' Modify the permisssion of the archiving script '''

        rights = stat.S_IRWXU
        try:
            implement_file(self.path, self.name, rights)
        except MyFileNotFound as exc:
            raise Error.erreurfatale(MyFileNotFound)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure)

############################################################################################################################################################
############################################################################################################################################################

def main():
    ''' Check if the archiving script and executing task already exist, update, create or remove them if necessary '''

    module = AnsibleModule(
        argument_spec = dict(
            username = dict(type = 'str', required = True),
            password = dict(type = 'str', required = True),
            host = dict(type = 'str', required = True),
            state = dict(required = True, choices = ['present', 'absent']),
            ARCHIVING_SCRIPT_PATH = dict(required = True, type = 'str'),
            SSH_PATH = dict(required = True, type = 'str'),
            ARCHIVING_SCRIPT_NAME = dict(required = True, type = 'str'),
            RSA_FILE = dict(required = True, type = 'str'),
            PUB_RSA_FILE = dict(required = True, type = 'str'),
            ARCHIVING_COMMANDS_LIST = dict(required = True, type = 'list')
        )
    )

    username = module.params.get('username')
    password = module.params.get('username')
    host = module.params.get('host')
    state = module.params.get('state')

    # Objects establishing for the archiving script and rsa key generation
    script = archives()
    link = ssh()

    if state.lower() == "absent":
        if script.existing_file is True:
            try:
                os.remove(script.path, script.name)
                module.exit_json(changed = True, msg = "Archiving script has been removed.")
            except IOError:
                raise Error.no_privileges(IOError)
        module.exit_json(changed = False, msg = "Archiving script has not been found.")
    
    elif state.lower() == "present":
        # If the archiving script exists, checking if the username and the target machine are good
        # Yes, no change needed
        # No, updating the script
        if script.existing_file is True:
            try:
                script.search(username)
                script.search(host)
                module.exit_json(changed = False, msg = "Archiving script already exists.")
            except EmptySearch as exc:
                script.create_commands(host, username)
                script.write_commands()
                module.exit_json(changed = True, msg = "Archiving script has been updated with new host or user.")
        # If not, creating the script
        else:
            script.create_commands(host, username)
            script.write_commands()
            module.exit_json(changed = True, msg = "Archiving script has been created.")

    else:
        raise Error.state_argument_error(state)

if __name__ == '__main__':

    main()