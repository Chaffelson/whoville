#!/usr/bin/env bash

# Launch Centos 7 Vm
# should have at least 4 cores / 14Gb mem / 20Gb disk
#### Copy/paste the following until the blank line to prep the instance
sudo su -
echo Patching...
yum update -y
echo Host Setup...
# The following should really be a systemd service
sudo yum install -y wget
sudo wget -nv http://public-repo-1.hortonworks.com/ambari/centos7/2.x/updates/2.5.1.0/ambari.repo -O /etc/yum.repos.d/ambari.repo
sudo yum repolist
echo Installing Packages...
sudo yum localinstall -y https://dev.mysql.com/get/mysql57-community-release-el7-8.noarch.rpm
sudo yum install -y git python-argparse epel-release mysql-connector-java* mysql-community-server
# MySQL Setup to keep the new services separate from the originals
echo Database setup...
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
echo Installing Ambari
export install_ambari_agent=true
export install_ambari_server=true
export java_provider=oracle
export ambari_version=2.5.1.0
curl -sSL https://raw.githubusercontent.com/seanorama/ambari-bootstrap/master/ambari-bootstrap.sh | sudo -E sh
sudo ambari-server setup --jdbc-db=mysql --jdbc-driver=/usr/share/java/mysql-connector-java.jar
sudo ambari-server install-mpack --verbose --mpack=http://public-repo-1.hortonworks.com/HDF/centos7/3.x/updates/3.0.0.0/tars/hdf_ambari_mp/hdf-ambari-mpack-3.0.0.0-453.tar.gz
# Hack to fix a current bug in Ambari Blueprints
sudo sed -i.bak "s/\(^    total_sinks_count = \)0$/\11/" /var/lib/ambari-server/resources/stacks/HDP/2.0.6/services/stack_advisor.py
sudo ambari-server restart
# Ambari blueprint cluster install
echo Deploying HDP and HDF services
export ambari_services="AMBARI_METRICS HDFS MAPREDUCE2 YARN ZOOKEEPER DRUID STREAMLINE NIFI KAFKA STORM REGISTRY"
export cluster_name=Whoville
export ambari_stack_version=2.6
export host_count=1
curl -ssLO https://github.com/seanorama/ambari-bootstrap/archive/master.zip
unzip -q master.zip -d  /root/
cd /root/ambari-bootstrap-master/deploy
# Blueprint
curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/ambariBlueprint_minimal-HDF.json > configuration-custom.json
# This command might fail with 'resources' error, means Ambari isn't ready yet
sleep 30
sudo -E /root/ambari-bootstrap-master/deploy/deploy-recommended-cluster.bash
echo 'if you get the error KeyError: resources then Ambari was too slow to come up, wait a minute and rerun "sudo -E /home/centos/ambari-bootstrap-master/deploy/deploy-recommended-cluster.bash"'
echo Now open your browser to http://$(curl -s icanhazptr.com):8080 and login as admin/admin to observe the cluster install