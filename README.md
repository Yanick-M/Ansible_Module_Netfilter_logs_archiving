# Ansible_Module_Netfilter_logs_archiving
To create a daemon with iptables rules, add prefix to netfilter logs, export own netfilter logs and archive the netfilter logs on remote server every day

![alt text](https://whiterivernow.com/wp-content/uploads/2018/12/Under-Construction-Sign.png)

    Cette librairie ansible a été développé afin de pouvoir archiver les logs Netfilter des serveurs et centraliser ces archives sur une machine dédiée.

Pour effectuer cette tâche, il est préférable de rendre les règles de Netfilter via IPtables persistantes dans un premier temps, puis de générer des
fichiers spécifiques aux logs de Netfilter grâce à rsyslog et logrotate et, enfin, de transmettre une archive des fichiers générés par logrotate vers la machine dédiée.

Afin de rendre "Netfilter" persistent, le module "iptables_save" va permettre de réaliser une sauvegarde des règles déjà en place puis de stocker une copie
de la sauvegarde sur la machine dédiée. La sauvegarde sera enregistrée dans le répertoire "/etc/init.d/" et sera utilisée par le module suivant. La copie pourra être téléchargée par le module si jamais il ne trouve pas le fichier sur la machine. Cette copie pourra également être analysée par la suite afin d'améliorer ou affiner les règles du pare-feu.
Ensuite, le module "daemon_script" va générer un fichier bash se comportant comme un démon à partir de trois éléments : une liste contenant le template par 
défaut, une liste contenant les préfixes à inclure dans les logs de Netfilter et la commande "iptables-restore" pointant vers la sauvegarde effectuée avec le précédent module. Un exemple des deux listes se trouvent dans le lien suivant et il est conseillé de ne pas modifier le template du démon : https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/persistent_firewall/vars/main.yml. Le script sera enregistré dans le répertoire "/etc/init.d/" et une copie sera transféré vers la machine dédiée. Lors de son exécution, le module va également chercher en premier lieu à télécharger une copie du script bash avant de le créer. Le module rend le démon actif et le démarre.

En ce qui concerne la gestion des logs, le module "own_logs" va générer un fichier conf pour le service rsyslog. Pour chaque préfixe indiqué dans la liste 
"IPTABLES_RULES_LIST", rsyslog enregistrera les informations dans un fichier spécifique à chacun d'entre eux dans le répertoire "/var/log/netfilter". Si le fichier "10-iptables.conf" existe déjà, celui-ci sera mis à jour si des préfixes n'existe pas.
Le module "logs_rotate" va générer un fichier conf pour le service logrotate. Tous les jours, une rotation des fichiers logs de Netfilter sera effectuée.
Un exemple du template du fichier conf : https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/firewall_logs/vars/main.yml. Dans le cas où celui-ci serait modifié, il faudra également répercuter les changements sur le script présenté dans la prochaine partie. Si le fichier existe déjà, il ne sera pas mis à jour.

Pour la compression et le transfert des logs, le module "archiving_task" va simplement ajouter dans la configuration crontab de root l'exécution d'un script
d'archivage (cf prochain module). Le fichier concerné est "/var/spool/cron/crontabs/root" car il confère une meilleure sécurité. La tâche s’exécute tous les jours à 07H00 juste après les tâches du service logrotate.
Pour finir, le module "archiving_script" va générer un script qui compressera les fichiers venant d'être créé par logrotate (par défaut, tous les fichiers
avec l'extension .1) et déplacera l'archive via ssh vers le serveur dédié. Le script sera enregistré dans "/root/" à partir de la liste : https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/logs_transfer/vars/main.yml.

A noter : les modules "iptables_save", own_logs" et "archiving_script" utilise le protocole ssh. Au cours de l'exécution de ces scripts, des clés pour
le super utilisateur root sont générés dans son répertoire "/root/.ssh/" avec le préfixe "id_rsa_archiving". La clé publique est ensuite transférée à la machine dédiée qui est automatiquement enregistrée dans le fichier "know_hosts". Tout ceci afin de permettre au script d'archivage de fonctionner sans intervention de l'utilisateur.

################################################################################################################################################################################################################################################################################################################################

    This ansible library was developed in order to be able to archive Netfilter logs from servers and centralize these archives on a dedicated machine.

    To perform this task, it is best to make persistent Netfilter rules via IPtables first and then generate specific files for Netfilter logs with rsyslog and 
logrotate and, finally, to send an archive of logs files, generated by logrotate, to the dedicated machine.

    In order to make "Netfilter" persistent, the "iptables_save" module will allow you to save the rules already in place and then store a copy of the backup 
on the dedicated machine. The backup will be saved in the "/etc/init.d/" directory and will be used by the next module. The copy can be downloaded an other time by the module if it does not find it on the machine. This copy can also be analyzed later in order to improve or refine the firewall rules.
    Then, the "daemon_script" module will generate a bash file behaving like a daemon from three elements: a list containing the template by default, a list
containing the prefixes to be included in the Netfilter logs and the "iptables-restore" command pointing to the backup made with the previous module. An example of the two lists can be found in the following link and it is advised not to modify the template of the daemon: https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/persistent_firewall/vars/main.yml. The script will be saved in the "/etc/init.d/" directory and a copy will be transferred to the dedicated machine. When running, the module will also first try to download a copy of the bash script before creating it. The module makes the daemon enable and starts it.

    Regarding log management, the "own_logs" module will generate a conf file for the rsyslog service. For each prefix indicated in the list 
"IPTABLES_RULES_LIST", rsyslog will record the information in a specific file for each of them in the "/ var / log / netfilter" directory. If the "10-iptables.conf" file already exists, it will be updated if any prefixes do not exist.
    The "logs_rotate" module will generate a conf file for the logrotate service. Every day, a rotation of the Netfilter log files will be carried out. An
example of the template for the conf file: https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/firewall_logs/vars/main.yml. In the event that it is modified, it will also be necessary to reflect the changes on the script presented in the next part. If the file already exists, it will not be updated.

    For the compression and the transfer of the logs, the "archiving_task" module will simply add in the root's crontab configuration the execution of a script
archiving (see next module). The affected file is "/var/spool/cron/crontabs/root" because it provides better security. The task runs every day at 7:00 a.m. just after the logrotate service tasks.
    Finally, the "archiving_script" module will generate a script which will compress the files just created by logrotate (by default, all files with the
extension .1) and will move the archive via ssh to the dedicated server. The script will be saved in "/root/" from the list: https://github.com/Yanick-M/Ansible_Module_Netfilter_logs_archiving/blob/main/roles/logs_transfer/vars/main.yml.

    Note: the "iptables_save", own_logs "and" archiving_script "modules use the ssh protocol. During the execution of these scripts, keys for
the super user root are generated in his "/root/.ssh/" directory with the prefix "id_rsa_archiving". The public key is then transferred to the dedicated machine which is automatically recorded in the "know_hosts" file. All this in order to allow the archive script to function without user intervention.
