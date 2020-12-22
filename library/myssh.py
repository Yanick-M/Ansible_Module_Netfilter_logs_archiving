#! /usr/bin/python3
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
from ansible.module_utils.basic import *
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

    def download_file(self, path, dest_path, name, module):
        ''' Download a file from the target machine '''
    
        try:
            if self.client is None:
                self.client = self.__connect()
            self.scp.get('{}{}'.format(dest_path, name), '{}{}'.format(path, name))
            msg = "File has been downloaded."
            return True, msg
        except:
            module.warn("-----Unable to download the file {} from {}-----".format(name, self.host.upper()))
            msg = "-----Unable to download the file {} from {}-----".format(name, self.host.upper())
            return False, msg

    def upload_file(self, path, dest_path, name, module):
        ''' Transfer a file on the target machine (create directories if they don't exists but not possible on root) '''

        try:
            if self.client is None:
                self.client = self.__connect()
            self._exec_command("mkdir -p {}".format(dest_path), module)
            self.scp.put('{}{}'.format(path, name), recursive=True, remote_path = dest_path)
            msg = "File has been uploaded."
            return True, msg
        except:
            module.warn("-----Unable to upload the file {} on {}-----".format(name, self.host.upper()))
            msg = "-----Unable to upload the file {} on {}-----".format(name, self.host.upper())
            return False, msg

############################################################################################################################################################
############################################################################################################################################################

def create_connection(module):
    
    link = ssh(module)
    msg = "ssh connection is enable"
    return True, msg

def make_download(module):
    
    link = ssh(module)
    result = link.download_file(module)
    return result

def make_upload(module):
    
    link = ssh(module)
    result = link.upload_file(module)
    return result

def main():
    
    fields = {
            "username": {"required": True, "type": "str"},
            "password": {"required": True, "no_log": True, "type": "str"},
            "host": {"required": True, "type": "str"},
            "SSH_PATH": {"default": "/root/.ssh/", "type": "str"},
            "RSA_FILE": {"default": "id_rsa_archiving", "type": "str"},
            "PUB_RSA_FILE": {"default": "id_rsa_archiving.pub", "type": "str"},
            "path": {"default": "/etc/init.d/", "type": "str"},
            "dest_path": {"default": "/LogsArchiving_REPO/", "type": "str"},
            "filename": {"required": False, "type"}
            "state": {
                "default": "enable", 
                "choices": ['enable', 'download', 'upload'],  
                "type": 'str' 
                }
            }

    choice_map = {
        "enable": create_connection,
        "download": make_download,
        "upload": make_upload
        }

    module = AnsibleModule(argument_spec = fields)

    has_changed, result = choice_map.get(module.params['state'])(module)
    module.exit_json(changed=has_changed, msg=result)

############################################################################################################################################################
############################################################################################################################################################

if __name__ == '__main__':

    main()