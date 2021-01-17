# Archiving Netfilter logs

## Description: 
The purpose of this project, under python 3.7, is to archive logs from the Netfilter firewall of a server running on Debian-based or RHEL-based distributions. Archiving is carried out daily by compressing the various files containing the logs of the day before and transferring them to a dedicated machine.

## Table of contents:  
  - [How it works:](#how-it-works)
      - [- Make persistent Netfilter rules:](#--make-persistent-netfilter-rules)
      - [- Extract Netfilter logs and set up files rotation:](#--extract-netfilter-logs-and-set-up-files-rotation)
      - [- Plan and implement an archiving script:](#--plan-and-implement-an-archiving-script)
      - [- Communication with the machine dedicated to archive storage](#--communication-with-the-machine-dedicated-to-archive-storage)
  - [Installing:](#installing)
  - [Using:](#using)
  - [Prerequisite:](#prerequisite)
  - [Version:](#version)
  - [License:](#license)

## How it works: 
   #### - Make persistent Netfilter rules:
1. ***Saving rules with IPtables (module iptables-save.py):***  
The objective of this module is to ensure that the firewall rules are backed up:  
       * Check the presence of the backup file,  
       * If this is not the case, download a copy of the file from the dedicated machine,  
       * Otherwise, save the rules and transfer a copy to the dedicated machine.  
>The backup is performed with the "iptables-save" command.  
>It is stored locally in the "/etc/init.d/" directory.  
>Its name is the combination of the "backup_iptables_" prefix and the name of the machine ("hostname").  
2. ***Set up a "Netfilter" daemon (module daemon_script.py):***  
The objective of this module is to make sure that a daemon is executed at startup and that it contains the list of log rules to be implemented:  
       * Check the presence of the script or download it from the dedicated machine if necessary,  
       * Compare the existing rules in the script with those to be implemented ; Update the script in case of difference,  
       * If the script or the copy does not exist, create the file from a template in which will be added the list of rules to be implemented as well as the command to restore the previously saved rules.  
>The script is stored in the "/etc/init.d/" directory.  
>Its name is the combination of the "firewall_" prefix and the name of the machine ("hostname").  
>The list of rules to be implemented is inserted under the "# Comments" line of the template.  
>The command to restore rules is inserted under the "# Restore iptables" line of the template.  
>It is of the form "iptables-restore < backup_iptables_$hostname".  
>The command used to start the daemon at startup is "update-rc.d" and its option "defaults".  
>The [template](https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/Persistent_firewall/vars/main.yml) of the daemon must be called as var. In my ansible structure, the var is a list defined in "Persistent_firewall" role vars.  
>The [list of rules](https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/group_vars/all) to be defined must be called as var. In my ansible structure, the var is a list defined in "group_vars" specific folder because it is used in several modules.  
   #### - Extract Netfilter logs and set up files rotation:
1. ***Configure rsyslog (module own_logs.py):***  
The objective of this module is to make sure that a conf file for rsyslog exists for the Netfilter logs:  
       * Check if the file exists,  
       * Check if the rules to be defined are already configured,  
       * Create the file or update it if necessary.  
>The conf file is stored in the "/etc/rsyslog.d/" directory.  
>It is called "10-iptables.conf".  
>The firewall logs will be stored in the "/var/log/netfilter/" directory.  
>Each log rule will have its own file whose name is the defined prefix.  
>The "rsyslog" service must be restarted if the conf file is created or modified.  
>The [list of rules](https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/group_vars/all) to be defined must be called as var. In my ansible structure, the var is a list defined in "group_vars" specific folder because it is used in several modules.  
2. ***Configure logrotate (module logs_rotate.py):***  
The objective of this module is to make sure that a conf file for logrotate exists for the Netfilter logs:  
       * Check if the file exists,  
       * Create the file from a template if necessary.  
> The conf file is stored in the "/etc/logrotate.d/" directory.  
> It is called "netfilter.conf".    
>The logrotate conf [template](https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/Firewall_logs/vars/main.yml) must be called as var.In my ansible structure, the var is a list defined in "Firewall_logs" role vars.  
   #### - Plan and implement an archiving script:
1. ***Configure cron (module archiving_task.py):***  
The objective of this module is to ensure that the execution of the script is scheduled at 7:00 a.m. every day:  
       * Check if the root crontab file exists,  
       * Check if the name of the archiving script is present in the file,  
       * Create the file or task if applicable.  
> The file is stored in the "/var/spool/cron/crontabs/" directory.  
> The file is called "root".  
> The task runs "netfilter_logs_archiving.sh" file which is created with the next module.  
2. ***generate the archiving script (module archiving_script.py):***  
The objective of this module is to ensure that the archive script is present:  
       * Check if the file exists,  
       * Check if the connection information for the dedicated machine is correct,  
       * Create or update the file as needed.  
> The file is stored in the "/root/" directory.  
> The file is called "netfilter_logs_archiving.sh".  
> The script compresses all files with the extension "* .1" in the directory "/var/log/netfilter/".  
> The name of the archive is in the form "archive_$hostname-$date.tar.gz".  
> The script moves the archive to the dedicated machine in its own directory and a sub-directory made up of the current month and year (example: "December2020/").  
>The [template](https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/Logs_transfer/vars/main.yml) must be called as var. In my ansible structure, the var is a list defined in "Logs_transfer" role vars.  
   #### - Communication with the machine dedicated to archive storage
The "persistent", "iptables-save" and "archiving_script" modules use the SSH protocol to communicate with the machine dedicated to archiving the logs and files required by the daemon. It is necessary to ensure that the id keys are present:  
    * Check if the files are present,  
    * Generate the files, transfer the public key and define the dedicated machine as a known host if necessary.  
> Keys use 4096 bit RSA encryption.  
> They are stored in the "/root/.ssh/" directory.  
> They are called "id_rsa_archiving" and "id_rsa_archiving.pub".  
> The files are stored on the dedicated machine in the "/LogsArchiving_REPO/" directory.  
> Each client has his own directory created from his name ("hostname"), inside the repository.  

## Installing:  
1. ***Zip file:***  
Download project as a zip archive by clicking [here](https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/archive/main.zip). 
Unzip archive in your workspace.
1. ***Clone project:***  
The second option consists in cloning the project with git.  
Get in your workspace or temprary directory and execute clone command like this.  
```cd /tmp/
git clone https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving  
```
3. ***Add library:***  
Copy the location of the library (like "/tmp/Ansible_Module_Netfilter_logs_archiving/library/").  
Open the file "/etc/ansible/ansible.cfg".  
Edit the line "library" at the beginning of the file and add ":" just follow by the library location.  
```For example :
library = /usr/share/my_modules/:/tmp/Ansible_Module_Netfilter_logs_archiving/library/
```
You can use others solutions [here](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html).  

## Using:  
Configure clients in "/etc/hosts" file.  
Then create your own inventory file (.ini or .yml) in "Ansible_Module_Netfilter_logs_archiving/" directory.  
Modify the list of IPtables commands in "/group_vars/all" to configure what you need.  
Modify playbook and roles if needed.  
Execute playbook from "Ansible_Module_Netfilter_logs_archiving/" directory.  
```For example :
ansible-playbook -b -i inventaire_labo.yml server_config.yml
```
You will have to enter informations for archiving ssh connection : host, user and password(securely, not shown on screen or in systems logs).  
Playbook is going to install needed packages, create Repo directory on dedicated machine (here, it's the Ansible server), then execute library on Ansible clients. For RHEL-based systems, playbook will configure logrotate cron jobs and stop logs flood on every console due to rsyslog.

## Prerequisite:  
* Having an Ansible service installed on a computer.
* This machine can communicate with ssh on the machines which have to be configure.
* Ansible clients can communicate with ssh on the dedicated machine which is going to store logs archive. 

## Version:  
1.1

## License:  
#### Copyright (c) 2020 [Yanick-M]
#### GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
