#!/usr/bin/env bash
# Launch Centos 7 Vm with at least 4 cores / 14Gb mem / 20Gb disk
# Then run:
# curl -sSL https://gist.github.com/abajwa-hw/f796bf572163518442632ecb0c9b2587/raw | sudo -E bash


export ambari_version=2.5.1.0
export mpack_url=http://public-repo-1.hortonworks.com/HDF/centos6/3.x/updates/3.0.1.1/tars/hdf_ambari_mp/hdf-ambari-mpack-3.0.1.1-5.tar.gz
#export mpack_url=http://public-repo-1.hortonworks.com/HDF/centos7/3.x/updates/3.0.0.0/tars/hdf_ambari_mp/hdf-ambari-mpack-3.0.0.0-453.tar.gz
export ambari_password=${ambari_password:-StrongPassword}
export db_password=${db_password:-StrongPassword}
export nifi_flow="https://gist.githubusercontent.com/abajwa-hw/3857a205d739473bb541490f6471cdba/raw"
#export nifi_flow="https://gist.githubusercontent.com/abajwa-hw/a78634099c82cd2bab1ccceb8cc2b86e/raw"
export host=$(hostname -f)


#echo Patching...
#yum update -y
#echo Host Setup...
# The following should really be a systemd service
#sudo yum install -y wget
#sudo wget -nv http://public-repo-1.hortonworks.com/ambari/centos7/2.x/updates/2.5.1.0/ambari.repo -O /etc/yum.repos.d/ambari.repo
#sudo yum repolist
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
# 2. sets passwords for druid/superset/registry/streamline users to ${db_password}
cat << EOF > mysql-setup.sql
ALTER USER 'root'@'localhost' IDENTIFIED BY 'Secur1ty!'; 
uninstall plugin validate_password;
CREATE DATABASE druid DEFAULT CHARACTER SET utf8; CREATE DATABASE superset DEFAULT CHARACTER SET utf8; CREATE DATABASE registry DEFAULT CHARACTER SET utf8; CREATE DATABASE streamline DEFAULT CHARACTER SET utf8; 
CREATE USER 'druid'@'%' IDENTIFIED BY '${db_password}'; CREATE USER 'superset'@'%' IDENTIFIED BY '${db_password}'; CREATE USER 'registry'@'%' IDENTIFIED BY '${db_password}'; CREATE USER 'streamline'@'%' IDENTIFIED BY '${db_password}'; 
GRANT ALL PRIVILEGES ON *.* TO 'druid'@'%' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON *.* TO 'superset'@'%' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON registry.* TO 'registry'@'%' WITH GRANT OPTION ; GRANT ALL PRIVILEGES ON streamline.* TO 'streamline'@'%' WITH GRANT OPTION ; 
commit; 
EOF
#execute sql file
mysql -h localhost -u root -p"$oldpass" --connect-expired-password < mysql-setup.sql
#change Mysql password to ${db_password}
mysqladmin -u root -p'Secur1ty!' password ${db_password}
#test password and confirm dbs created
mysql -u root -p${db_password} -e 'show databases;'
# Install Ambari251
echo Installing Ambari

export install_ambari_server=true
#export java_provider=oracle
curl -sSL https://raw.githubusercontent.com/seanorama/ambari-bootstrap/master/ambari-bootstrap.sh | sudo -E sh
sudo ambari-server setup --jdbc-db=mysql --jdbc-driver=/usr/share/java/mysql-connector-java.jar
sudo ambari-server install-mpack --verbose --mpack=${mpack_url}
# Hack to fix a current bug in Ambari Blueprints
sudo sed -i.bak "s/\(^    total_sinks_count = \)0$/\11/" /var/lib/ambari-server/resources/stacks/HDP/2.0.6/services/stack_advisor.py
#update admin password
curl -iv -u admin:admin -H "X-Requested-By: blah" -X PUT -d "{ \"Users\": { \"user_name\": \"admin\", \"old_password\": \"admin\", \"password\": \"${ambari_password}\" }}" http://localhost:8080/api/v1/users/admin

sudo ambari-server restart
# Ambari blueprint cluster install
echo Deploying HDP and HDF services
export ambari_services="AMBARI_METRICS HDFS MAPREDUCE2 YARN ZOOKEEPER DRUID STREAMLINE NIFI KAFKA STORM REGISTRY"
export cluster_name=Whoville
export ambari_stack_version=2.6
export host_count=1
curl -ssLO https://github.com/seanorama/ambari-bootstrap/archive/master.zip
unzip -q master.zip -d  /tmp


cd /tmp
echo downloading twitter flow
twitter_flow=$(curl -L ${nifi_flow})
#change kafka broker string for Ambari to replace later
twitter_flow=$(echo ${twitter_flow}  | sed "s/demo.hortonworks.com/${host}/g")
nifi_config="\"nifi-flow-env\" : { \"properties_attributes\" : { }, \"properties\" : { \"content\" : \"${twitter_flow}\"  }  },"
echo ${nifi_config} > nifi-config.json

echo downloading Blueprint configs template
curl -sSL https://gist.github.com/abajwa-hw/73be0ce6f2b88353125ae460547ece46/raw > configuration-custom-template.json

echo adding Nifi flow to blueprint configs template
sed -e "2r nifi-config.json" configuration-custom-template.json  > configuration-custom.json



cd /tmp/ambari-bootstrap-master/deploy
sudo cp /tmp/configuration-custom.json .


# This command might fail with 'resources' error, means Ambari isn't ready yet
echo Waiting for 30s for deploying
sleep 30
sudo -E /tmp/ambari-bootstrap-master/deploy/deploy-recommended-cluster.bash


echo Now open your browser to http://$(curl -s icanhazptr.com):8080 and login as admin/${ambari_password} to observe the cluster install

echo "Waiting for cluster to be installed..."
sleep 5

#wait until cluster deployed
ambari_pass="${ambari_password}" source /tmp/ambari-bootstrap-master/extras/ambari_functions.sh
ambari_configs
ambari_wait_request_complete 1


echo "Cluster installed...now setup trucking demo"

sudo yum install -y jq xml2


echo Downloading schemas...
curl -ssLO https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/schema_rawTruckEvents.avsc
curl -ssLO https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/schema_geoTruckEvents.avsc
curl -ssLO https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/schema_TruckSpeedEvents.avsc

echo Creating Schemas in Registry...
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "raw-truck_events_avro", "description": "Raw Geo events from trucks in Kafka Topic", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "raw-truck_speed_events_avro", "description": "Raw Speed Events from trucks in Kafka Topic", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "truck_events_avro", "description": "Schema for the kafka topic named truck_events_avro", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "truck_speed_events_avro", "description": "Schema for the kafka topic named truck_speed_events_avro", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas

echo Uploading schemas to registry...
curl -X POST -F 'name=raw-truck_events_avro' -F 'description=ver1' -F 'file=@./schema_rawTruckEvents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/raw-truck_events_avro/versions/upload
curl -X POST -F 'name=raw-truck_speed_events_avro' -F 'description=ver1' -F 'file=@./truckspeedevents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/raw-truck_speed_events_avro/versions/upload
curl -X POST -F 'name=truck_events_avro' -F 'description=ver1' -F 'file=@./schema_geoTruckEvents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/truck_events_avro/versions/upload
curl -X POST -F 'name=truck_speed_events_avro' -F 'description=ver1' -F 'file=@./schema_TruckSpeedEvents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/truck_speed_events_avro/versions/upload

echo Creating Kafka topics...
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper ${host}:2181 --replication-factor 1 --partition 1 --topic raw-truck_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper ${host}:2181 --replication-factor 1 --partition 1 --topic raw-truck_speed_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper ${host}:2181 --replication-factor 1 --partition 1 --topic truck_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper ${host}:2181 --replication-factor 1 --partition 1 --topic truck_speed_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --zookeeper ${host}:2181 --list


echo "Creating Hbase Tables..."
echo "create 'driver_speed','0'" | hbase shell
echo "create 'driver_violations','0'" | hbase shell


#TODO: add phoenix tables
createPhoenixTables () {
	/usr/hdp/current/phoenix-client/bin/sqlline.py $(hostname -f):2181:/hbase-unsecure $PHOENIX_PATH/create_tables.sql 
	/usr/hdp/current/phoenix-client/bin/psql.py -t DRIVERS $PHOENIX_PATH/data/drivers.csv
	/usr/hdp/current/phoenix-client/bin/psql.py -t TIMESHEET $PHOENIX_PATH/data/timesheet.csv
}

# set phoenix path for sql script and data
export PHOENIX_PATH=./phoenix

echo "Creating Phoenix Tables..."
# creating phoenix Tables
createPhoenixTables

#TODO: add SAM
#TODO: add missing schema
