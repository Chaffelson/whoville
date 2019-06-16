#!/bin/bash

# Install Anaconda
yum install -y bzip2 @development rh-python34
source /opt/rh/rh-python34/enable
export PYTHONHOME=/opt/rh/rh-python34/root/usr/
export PYTHONPATH=/opt/rh/rh-python34/root/usr/lib64/python3.4
pip3 install --upgrade pip
pip3 install requests pyopenssl
pip3 install https://github.com/Chaffelson/nipyapi/archive/efm.zip

# Install and setup EFM
# We need it after cluster start as we want NiFi Registry to be available
wget -q https://archive.cloudera.com/CEM/centos7/1.x/updates/1.0.0.0/CEM-1.0.0.0-centos7-tars-tarball.tar.gz -O /root/CEM-1.0.0.0-centos7-tars-tarball.tar.gz
tar -xzf /root/CEM-1.0.0.0-centos7-tars-tarball.tar.gz
mkdir /etc/efm
tar -xzf /root/CEM/centos7/1.0.0.0-54/tars/efm/efm-1.0.0.1.0.0.0-54-bin.tar.gz -C /etc/efm
chown -R root:root /etc/efm
export EFM_HOME='/etc/efm/efm-1.0.0.1.0.0.0-54/'
export PRIVATE_IP=$(hostname --ip-address)
sed -i "s@efm.server.address=localhost@efm.server.address=0.0.0.0@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.nifi.registry.enabled=false@efm.nifi.registry.enabled=true@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.nifi.registry.url=http://localhost:18080@efm.nifi.registry.url=http://${PRIVATE_IP}:61080@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.nifi.registry.bucketName=@efm.nifi.registry.bucketName=efm@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.db.url=jdbc:h2:./database/efm;AUTOCOMMIT=OFF;DB_CLOSE_ON_EXIT=FALSE;LOCK_MODE=3@efm.db.url=jdbc:mysql://${PRIVATE_IP}:3306/efm@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.db.driverClass=org.h2.Driver@efm.db.driverClass=com.mysql.jdbc.Driver@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.db.password=@efm.db.password=efm@g" ${EFM_HOME}/conf/efm.properties

# Install and setup MiNiFi-cpp
mkdir /etc/minifi-cpp
#wget -q http://www.mirrorservice.org/sites/ftp.apache.org/nifi/nifi-minifi-cpp/0.6.0/nifi-minifi-cpp-centos-0.6.0-bin.tar.gz -O /root/nifi-minifi-cpp-centos-0.6.0-bin.tar.gz
#tar -xzf /root/nifi-minifi-cpp-centos-0.6.0-bin.tar.gz -C /etc/minifi-cpp/
tar -xzf /root/CEM/centos7/1.0.0.0-54/tars/nifi-minifi-cpp/nifi-minifi-cpp-0.6.0-bin.tar.gz -C /etc/minifi-cpp/
chown -R root:root /etc/minifi-cpp
export MINIFICPP_HOME='/etc/minifi-cpp/nifi-minifi-cpp-0.6.0'
sed -i "s@#nifi.c2.@nifi.c2.@g" ${MINIFICPP_HOME}/conf/minifi.properties
sed -i "s@nifi.c2.agent.protocol.class=CoapProtocol@nifi.c2.agent.protocol.class=RESTSender@g" ${MINIFICPP_HOME}/conf/minifi.properties
sed -i "s@nifi.c2.agent.class=@nifi.c2.agent.class=minificpp@g" ${MINIFICPP_HOME}/conf/minifi.properties
sed -i "s@nifi.c2.rest.url=@nifi.c2.rest.url=http://${PRIVATE_IP}:10080/efm/api/c2-protocol/heartbeat@g" ${MINIFICPP_HOME}/conf/minifi.properties
sed -i "s@nifi.c2.rest.url.ack=@nifi.c2.rest.url.ack=http://${PRIVATE_IP}:10080/efm/api/c2-protocol/acknowledge@g" ${MINIFICPP_HOME}/conf/minifi.properties


# Install and setup MiNiFi-java
mkdir /etc/minifi-java
tar -xzf /root/CEM/centos7/1.0.0.0-54/tars/minifi/minifi-0.6.0.1.0.0.0-54-bin.tar.gz -C /etc/minifi-java/
chown -R root:root /etc/minifi-java
export MINIFIJAVA_HOME='/etc/minifi-java/minifi-0.6.0.1.0.0.0-54'
wget -q https://s3.eu-west-2.amazonaws.com/whoville/v2/nifi-kafka-2-0-nar-1.8.0.nar -O ${MINIFIJAVA_HOME}/lib/nifi-kafka-2-0-nar-1.8.0.nar
wget -q https://s3.eu-west-2.amazonaws.com/whoville/v2/nifi-standard-services-api-nar-1.8.0.nar ${MINIFIJAVA_HOME}/lib/nifi-standard-services-api-nar-1.8.0.nar
sed -i "s@#nifi.c2.@nifi.c2.@g" ${MINIFIJAVA_HOME}/conf/bootstrap.conf
sed -i "s@nifi.c2.agent.class=@nifi.c2.agent.class=minifijava@g" ${MINIFIJAVA_HOME}/conf/bootstrap.conf
sed -i "s@nifi.c2.rest.url=@nifi.c2.rest.url=http://${PRIVATE_IP}:10080/efm/api/c2-protocol/heartbeat@g" ${MINIFIJAVA_HOME}/conf/bootstrap.conf
sed -i "s@nifi.c2.rest.url.ack=@nifi.c2.rest.url.ack=http://${PRIVATE_IP}:10080/efm/api/c2-protocol/acknowledge@g" ${MINIFIJAVA_HOME}/conf/bootstrap.conf

tee /root/prep_minifi.py <<-'EOF'
#!/usr/bin/python3

import socket
import nipyapi


host_name = socket.getfqdn()
nipyapi.utils.set_endpoint('http://' + host_name + ':61080/nifi-registry-api')

# Create bucket for EFM
try:
    _ = nipyapi.versioning.create_registry_bucket('efm')
except ValueError:
    pass

EOF

chmod +x /root/prep_minifi.py
python3 /root/prep_minifi.py

# Start MiNiFi Services
${EFM_HOME}/bin/efm.sh start &> start_efm.log &
${MINIFICPP_HOME}/bin/minifi.sh start &> start_minificpp.log &
${MINIFIJAVA_HOME}/bin/minifi.sh start &> start_minifijava.log &