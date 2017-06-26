#!/usr/bin/env bash

# Login to preferred AWS EC2 Zone
# Launch Instance
# Centos 7 HVM (with updates)
# t2.xlarge (smallest successfull test on 4x16)
# 25GiB SSD (Delete on Term)
# Security Group - All Traffic / MyIp
# Use preferred key
# Launch
# ssh centos@<external fqdn>
#### Copy/paste the following until the blank line to prep the instance
sudo su -
echo Patching...
yum repolist && yum makecache fast && sudo yum update -y
echo Host Setup...
# The following should really be a systemd service
cat << 'EOF2' > /root/update_hosts_file.sh
#!/bin/bash
MY_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
cat << EOF > /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
$MY_IP whoville.hortonworks.com
EOF
exit 0
EOF2
chmod u+x /root/update_hosts_file.sh
echo sh /root/update_hosts_file.sh >> /etc/rc.local
chmod +x /etc/rc.d/rc.local
source /root/update_hosts_file.sh
echo Installing Packages...
sudo yum localinstall -y https://dev.mysql.com/get/mysql57-community-release-el7-8.noarch.rpm
sudo yum install -y git python-argparse epel-release mysql-connector-java* mysql-community-server
# MySQL Setup to keep the new services separate from the originals
echo Secondary Database setup...
sudo systemctl enable mysqld.service
sudo systemctl start mysqld.service
#extract system generated Mysql password
oldpass=$( grep 'temporary.*root@localhost' /var/log/mysqld.log | tail -n 1 | sed 's/.*root@localhost: //' )
#create sql file that
# 1. reset Mysql password to temp value and create druid/superset/registry/streamline schemas and users
# 2. sets passwords for druid/superset/registry/streamline users to StrongPassword
cat << EOF > mysql-setup.sql
ALTER USER 'root'@'localhost' IDENTIFIED BY 'Secur1ty!'; 
uninstall plugin validate_password;
CREATE DATABASE druid DEFAULT CHARACTER SET utf8; CREATE DATABASE superset DEFAULT CHARACTER SET utf8; CREATE DATABASE registry DEFAULT CHARACTER SET utf8; CREATE DATABASE streamline DEFAULT CHARACTER SET utf8; 
CREATE USER 'druid'@'%' IDENTIFIED BY 'StrongPassword'; CREATE USER 'superset'@'%' IDENTIFIED BY 'StrongPassword'; CREATE USER 'registry'@'%' IDENTIFIED BY 'StrongPassword'; CREATE USER 'streamline'@'%' IDENTIFIED BY 'StrongPassword'; 
GRANT ALL PRIVILEGES ON *.* TO 'druid'@'%' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON *.* TO 'superset'@'%' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON registry.* TO 'registry'@'%' WITH GRANT OPTION ; GRANT ALL PRIVILEGES ON streamline.* TO 'streamline'@'%' WITH GRANT OPTION ; 
commit; 
EOF
#execute sql file
mysql -h localhost -u root -p"$oldpass" --connect-expired-password < mysql-setup.sql
#change Mysql password to StrongPassword
mysqladmin -u root -p'Secur1ty!' password StrongPassword
#test password and confirm dbs created
mysql -u root -pStrongPassword -e 'show databases;'
# Install Ambari251
echo Installing Primary Database, Java, and Ambari
export install_ambari_agent=true
export install_ambari_server=true
export java_provider=oracle
export ambari_version=2.5.1.0
curl -sSL https://raw.githubusercontent.com/seanorama/ambari-bootstrap/master/ambari-bootstrap.sh | sudo -E sh
sudo ambari-server setup --jdbc-db=mysql --jdbc-driver=/usr/share/java/mysql-connector-java.jar
echo Installing HDF mPack
sudo ambari-server install-mpack --verbose --mpack=http://public-repo-1.hortonworks.com/HDF/centos7/3.x/updates/3.0.0.0/tars/hdf_ambari_mp/hdf-ambari-mpack-3.0.0.0-453.tar.gz
# Hack to fix a current bug in Ambari Blueprints
echo Fix Ambari Bugs
sudo sed -i.bak "s/\(^    total_sinks_count = \)0$/\11/" /var/lib/ambari-server/resources/stacks/HDP/2.0.6/services/stack_advisor.py
sudo ambari-server restart
# Ambari blueprint cluster install
echo Deploying HDP and HDF services
sudo su -
export ambari_services="AMBARI_METRICS HDFS MAPREDUCE2 YARN ZOOKEEPER DRUID STREAMLINE NIFI KAFKA STORM REGISTRY"
export cluster_name=Whoville
export ambari_stack_version=2.6
export host_count=1
curl -ssLO https://github.com/seanorama/ambari-bootstrap/archive/master.zip
unzip -qo master.zip -d  /root/
cd /root/ambari-bootstrap-master/deploy
# Blueprint
echo Running Cluster Template deployment script
curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/ambariBlueprint_minimal-HDF.json > configuration-custom.json
# This next command might fail with 'resources' error, means Ambari isn't ready yet, so waiting 30s to let Ambari spin up
sleep 30
/root/ambari-bootstrap-master/deploy/deploy-recommended-cluster.bash
echo 'if you get the error KeyError: resources then Ambari was too slow to come up, wait a minute and rerun "sudo -E /home/centos/ambari-bootstrap-master/deploy/deploy-recommended-cluster.bash"'
echo Now open your browser to http://$(curl -s icanhazptr.com):8080 and login as admin/admin to observe the cluster install