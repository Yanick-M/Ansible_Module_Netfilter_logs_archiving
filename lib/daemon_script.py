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

############################################################################################################################################################
############################################################################################################################################################

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

class daemon:
    ''' Class to manage a "Netfilter Daemon" '''

    def __init__(self):
        ''' Initialize the object '''
        
        self.name = module.params.get("DAEMON_PREFIX") + socket.gethostname()
        self.path = module.params.get('INITD_PATH')
        self.remote_path = module.params.get('REMOTE_PATH') + socket.gethostname() + "/"
        self.save_name = module.params.get("IPTABLES_PREFIX") + socket.gethostname()
        self._read()
        self.logs_rules = module.params.get('IPTABLES_RULES_LIST')
        self.bloc_A = module.params.get('BLOC_A')
        self.bloc_B = module.params.get('BLOC_B')

    def _read(self):
        ''' Check if the daemon script exists on the remote host '''
        
        try:
            self.daemon_commands = read_file(self.path, self.name)
            self.existing = True
        except MyFileNotFound as exc:
            self.existing = False
        except ReadingFailure as esc:
            raise Error.privileges(ReadingFailure)
    
    def download(self, link):
        ''' Download a copy of a previous script creation on the remote host from the target machine '''
        
        link.download_file(self.path, self.remote_path, self.name)
        self._read()

    def upload(self, link):
        ''' Upload a copy of the script from the remote host to the target machine '''

        link.upload_file(self.path, self.remote_path, self.name)

    def _compare_logs_rules(self):
        ''' Check if desired iptables logs rules are already configured and save in a list which are not '''

        try:
            tables = read_file(self.path, self.save_name)
        except MyFileNotFound as exc:
            raise Error.file_missing(MyFileNotFound, self.path, self.save_name)
        self.all_rules = self.daemon_commands + tables
        self.rules_to_define = []
        
        print("-----data comparison-----")
        for rule in self.logs_rules:
            rule_found = False
            for command in self.daemon_commands:
                if rule == command or rule[9:] == command:
                    rule_found = True
                    break
            if rule_found is False:
                self.rules_to_define.append(rule)
        
        if not self.rules_to_define:
            raise EmptySearch

    def _find_bloc(self, bloc):
        ''' Check for the line number of a commentary in the script content '''
        
        print("-----looking for bloc {}-----".format(bloc))
        
        position = 0
        
        for command in self.daemon_commands:
        
            if command == bloc:
                break
            position += 1
        
        if position == len(self.daemon_commands):
            raise EmptySearch

        return(position)

    def update_script(self, link):
        ''' Rewrite the script with the new logs rules '''
            
        try:
            self._compare_logs_rules()
            try:
                self.bloc_A_position = self._find_bloc(self.bloc_A) + 1
            except EmptySearch as exc:
                raise Error.fatal_error(EmptySearch)
            self._update_commands(self.bloc_A_position, self.rules_to_define)
            self.write_commands(link)
        except EmptySearch as exc:
            raise NoUpDateNeeded

    def _update_commands(self, bloc_position, data):
        ''' Insert new logs rules commands in the content of the existing script '''
        
        print("-----insert missing commands in the daemon script-----")
        for rule in reversed(self.rules_to_define):
            self.daemon_commands.insert(bloc_position, rule)

    def write_commands(self, link):
        ''' Write the content in a file on the remote host '''

        try:
            write_file(self.path, self.name, self.daemon_commands)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure)
        
        self.implement()
        self.job.upload(link)
    
    def implement(self):
        ''' Change the permission of the script, declare and start the service '''

        # Le script nécessite des droits d'exécution , puis permet la création et le démarrage d'un daemon donc une fonction spécifique par rapport au fichier IPtables
        # Mise en place du fichier dans le répertoire de destination
        rights = stat.S_IRWXU
        try:
            implement_file(self.path, self.name, rights)
        except MyFileNotFound as exc:
            raise Error.erreurfatale(MyFileNotFound)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure)

        result = os.system('update-rc.d "{}" defaults > /dev/null 2>&1'.format(self.name))
        result2 = os.system('systemctl start {}service > /dev/null 2>&1'.format(self.name[:-2]))
        if result == 256 or result2 == 1280:
            raise ServiceFailure
    
    def create_commands(self):
        ''' Create the content of the script '''
        
        print("-----script creation-----")
        
        self.daemon_commands = module.params.get('DAEMON_COMMANDS_LIST')

        try:
            self._compare_logs_rules()
        except EmptySearch as exc:
            raise Error.fatal_error(EmptySearch)
        
        try:
            self.bloc_A_position = self._find_bloc(self.bloc_A) + 1
        except EmptySearch as exc:
            raise Error.fatal_error(EmptySearch)
        
        self._update_commands(self.bloc_A_position, self.rules_to_define)

        try:
            self.bloc_B_position = self._find_bloc(self.bloc_B) + 1
        except EmptySearch as exc:
            raise Error.fatal_error(EmptySearch)

        self.daemon_commands.insert()(self.bloc_B_position, "iptables-restore -n < \"{}{}\"".format(self.path, self.save_name))

############################################################################################################################################################
############################################################################################################################################################

def main():
    ''' Check if the daemon script already exists, update or create it if necessary '''
    
    module = AnsibleModule(
        argument_spec = dict(
            INITD_PATH = dict(required = True, type = 'str'),
            SSH_PATH = dict(required = True, type = 'str'),
            REMOTE_PATH = dict(required = True, type = 'str'),
            DAEMON_PREFIX = dict(required = True, type = 'str'),
            IPTABLES_PREFIX = dict(required= True, type = 'str'),
            RSA_FILE = dict(required = True, type = 'str'),
            PUB_RSA_FILE = dict(required = True, type = 'str'),
            IPTABLES_RULES_LIST = dict(required = True, type = 'list'),
            DAEMON_COMMANDS_LIST = dict(required = True, type = 'list'),
            BLOC_A = dict(required = True, type = 'str'),
            BLOC_B = dict(required = True, type = 'str'),
            username = dict(type = 'str', required = True),
            password = dict(type = 'str', required = True),
            host = dict(type = 'str', required = True),
            state = dict(required = True, choices = ['present', 'absent'])
    )
)

    username = module.params.get('username')
    password = module.params.get('username')
    host = module.params.get('host')
    state = module.params.get('state')

    # Objects establishing for the daemon and the ssh connection
    job = daemon()
    link = ssh(username, password, host)

    if state.lower() == "absent":
        if job.existing is True:
            try:
                os.remove(job.path, job.name)
                module.exit_json(changed = True, msg = "Netfilter daemon script has been removed.")
            except IOError:
                raise Error.no_privileges(IOError)   
        else:
            module.exit_json(changed = False, msg = "Netfilter daemon script has not been found.")

    elif state.lower() == "present":
        # If a script has been found in init.d directory, trying to see if the desired logs rules exists
        # No, the script is updated
        # Yes, the module is quit
        if job.existing is True:
            try:
                job.update_script(link)
                module.exit_json(changed = True, msg = "Daemon has been updated with new logs rules.")
            except NoUpDateNeeded as exc:
                module.exit_json(changed = False, msg = "Nelfilter daemon already exits.")
        # If not, trying to download it from remote server then updating if needed
        # If no save on the remote server, the script is generated      
        else:
            job.download(link)
            if job.existing is True:
                try:
                    job.update_script(link)
                    module.exit_json(changed = True, msg = "Daemon has been downloaded and updated with new logs rules.")
                except NoUpDateNeeded as exc:
                    job.implement()
                    module.exit_json(changed = True, msg = "Up to date netfilter daemon has been downloaded from remote server.")
            else:
                job.create_commands()
                job.write_commands(link)
                module.exit_json(changed = True, msg = "Daemon has been created with desired logs rules.")

    else:
        raise Error.state_argument_error(state)

############################################################################################################################################################
############################################################################################################################################################

if __name__ == '__main__':

    main()