#!/usr/bin/env bash
# Credit to: https://lonesysadmin.net/2013/03/26/preparing-linux-template-vms/
sudo su -
echo Stopping Ambari Services
ambari-agent stop
ambari-server stop
echo Stopping Databases
systemctl stop mysqld.service
systemctl stop postgresql.service
echo Stopping Log and Audit services
/sbin/service rsyslog stop
/sbin/service auditd stop
echo Cleaning up Packages
package-cleanup -y --oldkernels --count=1
yum -y clean all
echo Clearing down logs
rm -f /var/log/*-???????? 
rm -f /var/log/*.gz
rm -f /var/log/dmesg.old
cat /dev/null > /var/log/audit/audit.log
cat /dev/null > /var/log/wtmp
cat /dev/null > /var/log/lastlog
cat /dev/null > /var/log/grubby
echo Cleaning up temp files
rm -rf /tmp/*
rm -rf /var/tmp/*
echo Clearing out bash history
rm -f ~root/.bash_history
rm -f /home/centos/.bash_history
unset HISTFILE
echo Clearing ssh keys
rm -f /etc/ssh/*key*
rm -rf ~root/.ssh/
rm -rf /home/centos/.ssh
sed -i.bak 's/ssh_deletekeys:   0/ssh_deletekeys:   1/g' /etc/cloud/cloud.cfg
echo Ready to 'sudo shutdown now' for imaging
