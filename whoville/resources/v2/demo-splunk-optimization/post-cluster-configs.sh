#!/bin/bash

# Install Anaconda
yum install -y bzip2 @development rh-python34
source /opt/rh/rh-python34/enable
export PYTHONHOME=/opt/rh/rh-python34/root/usr/
export PYTHONPATH=/opt/rh/rh-python34/root/usr/lib64/python3.4
pip3 install --upgrade pip
pip3 install requests pyopenssl
sudo yum -y install jq

# Install and configure aws cli
pip install awscli --upgrade --user

# Install eksctl

curl --silent --location "https://github.com/weaveworks/eksctl/releases/download/latest_release/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# Install kubectl
sudo curl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl
sudo chmod a+x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl

# Create kubectl deployment
sudo mkdir /home/nifi/minifi-k8s/
sudo chown nifi:hadoop /home/nifi/minifi-k8s/
export PRIVATE_IP=$(hostname --ip-address)


sudo cat << EOF > /home/nifi/minifi-k8s/minifi.yml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: minifi
spec:
  replicas: 1
  selector:
    matchLabels:
      app: minifi
  template:
    metadata:
      labels:
        app: minifi
    spec:
      containers:
      - name: minifi-container
        image: paulvid/minifi-java-splunk-demo
        ports:
        - containerPort: 10080
          name: http
        - containerPort: 6065
          name: listenhttp  
        - containerPort: 22
          name: ssh
        resources:
          requests:
            cpu: "500m"
            memory: "1Gi"
          limits:
            cpu: "1"
        env:
        - name: NIFI_C2_ENABLE
          value: "true"
        - name: MINIFI_AGENT_CLASS
          value: "listenSysLog"
        - name: NIFI_C2_REST_URL
          value: http://${PRIVATE_IP}:10080/efm/api/c2-protocol/heartbeat
        - name: NIFI_C2_REST_URL_ACK
          value: http://${PRIVATE_IP}:10080/efm/api/c2-protocol/acknowledge
---
kind: Service             #+
apiVersion: v1            #+
metadata:                 #+
  name: minifi-service     #+
spec:                     #+
  selector:               #+
    app: minifi            #+
  ports:                  #+
  - protocol: TCP         #+
    targetPort: 10080     #+
    port: 10080              #+
    name: http            #+
  - protocol: TCP         #+
    targetPort: 9877     #+
    port: 9877              #+
    name: tcpsyslog    
  - protocol: TCP         #+
    targetPort: 9878     #+
    port: 9878             #+
    name: udpsyslog   
  - protocol: TCP         #+
    targetPort: 22        #+
    port: 22              #+
    name: ssh             #+
  - protocol: TCP         #+
    targetPort: 6065        #+
    port: 6065              #+
    name: listenhttp             #+
  type: LoadBalancer      #+
  loadBalancerSourceRanges:
  - 0.0.0.0/0
EOF

sudo chown nifi:hadoop /home/nifi/minifi-k8s/minifi.yml

# Finally cloning the scripts we need 

sudo wget -O /home/nifi/minifi-k8s/launch_aks_cluster.sh https://gist.githubusercontent.com/paulvid/ae7f0ec16baada158a45b2f803114c45/raw/20865ead5a32796d05510d11965235c904a6ce86/launch_aks_cluster.sh
sudo chmod a+x /home/nifi/minifi-k8s/launch_aks_cluster.sh
sudo chown nifi:hadoop /home/nifi/minifi-k8s/launch_aks_cluster.sh

sudo wget -O /home/nifi/minifi-k8s/delete_aks_cluster.sh https://gist.githubusercontent.com/paulvid/ecd220cda30dc99761ddc8d7935fe205/raw/1dcdbd6d87a3f22235890b0b571428079a59e171/delete_aks_cluster.sh
sudo chmod a+x /home/nifi/minifi-k8s/delete_aks_cluster.sh
sudo chown nifi:hadoop /home/nifi/minifi-k8s/delete_aks_cluster.sh


# Install and setup EFM
# We need it after cluster start as we want NiFi Registry to be available
wget -q https://archive.cloudera.com/CEM/centos7/1.x/updates/1.0.0.0/CEM-1.0.0.0-centos7-tars-tarball.tar.gz -O /root/CEM-1.0.0.0-centos7-tars-tarball.tar.gz
tar -xzf /root/CEM-1.0.0.0-centos7-tars-tarball.tar.gz
mkdir /etc/efm
tar -xzf /root/CEM/centos7/1.0.0.0-54/tars/efm/efm-1.0.0.1.0.0.0-54-bin.tar.gz -C /etc/efm
chown -R root:root /etc/efm
export EFM_HOME='/etc/efm/efm-1.0.0.1.0.0.0-54/'

sed -i "s@efm.server.address=localhost@efm.server.address=0.0.0.0@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.nifi.registry.enabled=false@efm.nifi.registry.enabled=true@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.nifi.registry.url=http://localhost:18080@efm.nifi.registry.url=http://${PRIVATE_IP}:61080@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.nifi.registry.bucketName=@efm.nifi.registry.bucketName=efm@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.db.url=jdbc:h2:./database/efm;AUTOCOMMIT=OFF;DB_CLOSE_ON_EXIT=FALSE;LOCK_MODE=3@efm.db.url=jdbc:mysql://${PRIVATE_IP}:3306/efm@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.db.driverClass=org.h2.Driver@efm.db.driverClass=com.mysql.jdbc.Driver@g" ${EFM_HOME}/conf/efm.properties
sed -i "s@efm.db.password=@efm.db.password=efm@g" ${EFM_HOME}/conf/efm.properties


# Setup bucket

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


