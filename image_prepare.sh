#!/usr/bin/env bash
# Credit to: https://lonesysadmin.net/2013/03/26/preparing-linux-template-vms/
sudo su -
curl -u admin:admin -i -H 'X-Requested-By: ambari' -X PUT \
   -d '{"RequestInfo":{"context":"_PARSE_.STOP.ALL_SERVICES","operation_level":{"level":"CLUSTER","cluster_name":"whoville"}},"Body":{"ServiceInfo":{"state":"INSTALLED"}}}' \
   http://localhost:8080/api/v1/clusters/whoville/services
ambari-agent stop
ambari-server stop
systemctl stop mysqld.service
systemctl stop postgresql.service
/sbin/service rsyslog stop
/sbin/service auditd stop
package-cleanup -y --oldkernels --count=1
yum -y clean all
rm -f /var/log/*-???????? 
rm -f /var/log/*.gz
rm -f /var/log/dmesg.old
cat /dev/null > /var/log/audit/audit.log
cat /dev/null > /var/log/wtmp
cat /dev/null > /var/log/lastlog
cat /dev/null > /var/log/grubby
rm -rf /tmp/*
rm -rf /var/tmp/*
rm -f /etc/ssh/*key*
rm -f ~root/.bash_history
unset HISTFILE
rm -rf ~root/.ssh/
rm -rf /home/centos/.ssh
echo Ready to 'shutdown now' for imaging
