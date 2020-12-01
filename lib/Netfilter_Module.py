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

module = AnsibleModule(argument_spec=dict(
    PATH_DAEMON = dict(required = True, type = 'str'),
    RSYSLOG_PATH = dict(required = True, type = 'str'),
    LOGS_PATH = dict(required = True, type = 'str'),
    LOGROTATE_PATH = dict(required = True, type = 'str'),
    CRONTAB_PATH = dict(required = True, type = 'str'),
    ARCHIVING_SCRIPT_PATH = dict(required = True, type = 'str'),
    SSH_PATH = dict(required = True, type = 'str'),
    REMOTE_PATH = dict(required = True, type = 'str'),
    DAEMON_PREFIX = dict(required = True, type = 'str'),
    IPTABLES_PREFIX = dict(required= True, type = 'str'),
    RSYSLOG_CONF_FILE = dict(required = True, type = 'str'),
    LOGROTATE_FILE_NAME = dict(required = True, type = 'str'),
    CRONTAB_FILE_NAME = dict(required = True, type = 'str'),
    ARCHIVING_SCRIPT_NAME = dict(required = True, type = 'str'),
    RSA_FILE = dict(required = True, type = 'str'),
    PUB_RSA_FILE = dict(required = True, type = 'str'),
    IPTABLES_RULES_LIST = dict(required = True, type = 'list'),
    DAEMON_COMMANDS_LIST = dict(required = True, type = 'list'),
    ARCHIVING_COMMANDS_LIST = dict(required = True, type = 'list'),
    LOGROTATE_LIST = dict(required = True, type = 'list'),
    BLOC_A = dict(required = True, type = 'str'),
    BLOC_B = dict(required = True, type = 'str')
))

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

class iptables:
    ''' Class to manage iptables save '''
    
    def __init__(self):
        ''' Initialize the object '''
        
        self.name = module.params.get("IPTABLES_PREFIX") + socket.gethostname()
        self.path = module.params.get('PATH_DAEMON')
        self.remote_path = module.params.get('REMOTE_PATH') + socket.gethostname() + "/"
        self._read()
        
    def _read(self):
        ''' Check if a save exists on the remote host ''' 
        
        try:
            self.rules_list = read_file(self.path, self.name)
            self.existing = True
        except MyFileNotFound as exc:
            self.existing = False
        except ReadingFailure as esc:
            raise Error.privileges(ReadingFailure)

    def download(self, link):
        ''' Download a copy of a previous save on the remote host from the target machine '''
        
        link.download_file(self.path, self.remote_path, self.name)
        self._read()

    def save(self):
        ''' Save the iptables rules on the remote host '''
    
        print("-----saving iptables rules-----")
        os.system("/usr/sbin/iptables-save > \"{}{}\"".format(self.path, self.name))
        self._read()

    def upload(self, link):
        ''' Upload a copy of the save from the remote host to the target machine '''

        link.upload_file(self.path, self.remote_path, self.name)

############################################################################################################################################################
############################################################################################################################################################

class daemon:
    ''' Class to manage a "Netfilter Daemon" '''

    def __init__(self):
        ''' Initialize the object '''
        
        self.name = module.params.get("DAEMON_PREFIX") + socket.gethostname()
        self.path = module.params.get('PATH_DAEMON')
        self.remote_path = module.params.get('REMOTE_PATH') + socket.gethostname() + "/"
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

        tables = iptables()
        self.all_rules = self.daemon_commands + tables.rules_list
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
        
        return(tables)

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
        self.job_daemon.upload(link)
    
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
            iptables_rules = self._compare_logs_rules()
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

        self.daemon_commands.insert()(self.bloc_B_position, "iptables-restore -n < \"{}{}\"".format(iptables_rules.path, iptables_rules.name))

############################################################################################################################################################
############################################################################################################################################################

class logs:
    ''' Class to manage Netfilter logs '''

    def __init__(self):
        ''' Initialize the object '''

        self.name = module.params.get('RSYSLOG_CONF_FILE')
        self.path = module.params.get('RSYSLOG_PATH')
        self.logs_path = module.params.get('LOGS_PATH')
        self.logs_rules = module.params.get('LOGS_RULES_LIST')
        self.logrotate_name = module.params.get('LOGROTATE_FILE_NAME')
        self.logrotate_path = module.params.get('LOGROTATE_PATH')
        self.logrotate_list = module.params.get('LOGROTATE_LIST')
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

    def check_log_rotation(self):
        ''' Check if logrotate conf file exists for Netfilter logs '''

        try:
            read_file(self.rotate_path, self.rotate_name)
        except MyFileNotFound as exc:
            self._create_logs_rotation()
        except ReadingFailure as exc:
            raise Error.no_privileges(ReadingFailure)

    def _create_logs_rotation(self):
        ''' Create logrotate conf file '''

        try:
            write_file(self.rotate_path, self.rotate_name, self.rotate_list)
        except WritingFailure as exc:
            raise Error.unable_to_write(WritingFailure, self.rotate_path, self.rotate_name)

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

def create_save_iptables():
    ''' Check if an iptables save already exists, update or create it if necessary '''
    
    # Specific function vars processing
    module_args = dict(
        username = dict(type = 'str', required = True),
        password = dict(type = 'str', required = True),
        host = dict(type = 'str', required = True),
    )
    username = module.params.get('username')
    password = module.params.get('username')
    host = module.params.get('host')

    # Objects establishing for iptables save and the ssh connection
    job_iptables = iptables()
    link = ssh(username, password, host)

    # If a save has been found in init.d directory, no change needed
    if job_iptables.existing is True:
        module.exit_json(changed = False, msg = "Netfilter rules are already saved.")
    else:
        # No, try to download a copy or make the save
        job_iptables.download(link)
        if job_iptables.existing is True:
            module.exit_json(changed = False, msg = "Netfilter save has been downloaded from remote server.")
        else:
            job_iptables.save()
            if job_iptables.existing is True:
                job_iptables.upload(link)
                module.exit_json(changed = True, msg = "Netfilter rules have been saved")
            else:
                module.fail_json(changed = False, msg = "Unable to save Netfilter rules" )

############################################################################################################################################################
############################################################################################################################################################

def create_netfilter_daemon():
    ''' Check if the daemon script already exists, update or create it if necessary '''

    # Specific function vars processing
    module_args = dict(
        username = dict(type = 'str', required = True),
        password = dict(type = 'str', required = True),
        host = dict(type = 'str', required = True),
    )
    username = module.params.get('username')
    password = module.params.get('username')
    host = module.params.get('host')

    # Objects establishing for the daemon and the ssh connection
    job_daemon = daemon()
    link = ssh(username, password, host)

    # If a script has been found in init.d directory, trying to see if the desired logs rules exists
    # No, the script is updated
    # Yes, the module is quit
    if job_daemon.existing is True:
        try:
            job_daemon.update_script(link)
            module.exit_json(changed = True, msg = "Daemon has been updated with new logs rules.")
        except NoUpDateNeeded as exc:
            module.exit_json(changed = False, msg = "Nelfilter daemon already exits.")
    # If not, trying to download it from remote server then updating if needed
    # If no save on the remote server, the script is generated      
    else:
        job_daemon.download(link)
        if job_daemon.existing is True:
            try:
                job_daemon.update_script(link)
                module.exit_json(changed = True, msg = "Daemon has been downloaded and updated with new logs rules.")
            except NoUpDateNeeded as exc:
                job_daemon.implement()
                module.exit_json(changed = True, msg = "Up to date netfilter daemon has been downloaded from remote server.")
        else:
            job_daemon.create_commands()
            job_daemon.write_commands(link)
            module.exit_json(changed = True, msg = "Daemon has been created with desired logs rules.")

############################################################################################################################################################
############################################################################################################################################################

def create_netfilter_own_logs():
    ''' Check if the rsyslog conf file already exists, update or create it if necessary '''
    
    # Object establishing for the Netfilter logs
    iptables_logs = logs()

    # If a rsyslog conf file exits, trying to see if the desired logs rules exists
    # No, rsyslog conf file is updated and logrotate check
    # Yes, just check logrotate
    if iptables_logs.existing is True:
        try:
            iptables_logs.compare_rsyslog_commands()
            iptables_logs.update_conf_file()
            iptables_logs.check_log_rotation()
            module.exit_json(changed = True, msg = "Rsyslog conf file has been updated with new Netfilter logs.")
        except EmptySearch as exc:
            iptables_logs.check_log_rotation()
            module.exit_json(changed = False, msg = "Netfilter has already his own logs.")
    # If not, create the conf files for rsyslog and logrotate
    else:
        iptables_logs.create_conf_file()
        iptables_logs.write_commands()
        iptables_logs.check_log_rotation()
        module.exit_json(changed = True, msg = "Rsyslog conf file has been created, Nefilter has is own logs")

############################################################################################################################################################
############################################################################################################################################################

def create_crontab_task():
    ''' Check if the root crontab file already exists, update or create it if necessary '''

    # Object establishing for the crontab task
    crontab = task()

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

############################################################################################################################################################
############################################################################################################################################################

def create_archiving_script():
    ''' Check if the archiving script already exists, update or create it if necessary '''

    # Specific function vars processing
    module_args = dict(
        username = dict(type = 'str', required = True),
        password = dict(type = 'str', required = True),
        host = dict(type = 'str', required = True),
        new = dict(type = 'bool', required = False, default = False)
        )
    username = module.params.get('username')
    password = module.params.get('username')
    host = module.params.get('host')

    # Object establishing for the archiving script
    script = archives()

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

############################################################################################################################################################
############################################################################################################################################################

def cancel_all_change():
    pass

############################################################################################################################################################
############################################################################################################################################################

if __name__ == '__main__':

    create_save_iptables()
    create_netfilter_daemon()
    create_netfilter_own_logs()
    create_crontab_task()
    create_archiving_script()