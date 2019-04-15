#!/bin/bash

install_utils () {
  cp -Rf /home/centos/.kube /root/.kube

  yum install -y wget
  yum install -y git
  yum install -y java-1.8.0-openjdk*
  yum install -y protobuf*
  yum install -y cmake

  wget http://repos.fedorapeople.org/repos/dchen/apache-maven/epel-apache-maven.repo -O /etc/yum.repos.d/epel-apache-maven.repo
  sed -i s/\$releasever/6/g /etc/yum.repos.d/epel-apache-maven.repo

  yum install -y apache-maven
  
  yum install -y epel-release
  yum -y install python-pip
  pip install awscli
}

build_hadoop () {
  git clone https://github.com/apache/hadoop
  cd hadoop
  mvn clean install package -DskipTests -Pdist,hdds -Dtar -Dmaven.javadoc.skip=true
  #mvn clean install package -Phdds -DskipTests=true -Dmaven.javadoc.skip=true -Pdist -Dtar -DskipShade -am -pl :hadoop-ozone-dist
  cd ..
}

build_ozone_container () {
  cd hadoop/hadoop-ozone/dist

tee start-scm.sh <<-'EOF'
bin/ozone scm --init
bin/ozone scm
EOF

tee start-om.sh <<-'EOF'
bin/ozone om --init
bin/ozone om
EOF
  
  chmod 755 start-om.sh
  chmod 755 start-scm.sh
  
  echo "ADD --chown=hadoop start-scm.sh /opt/hadoop" >> Dockerfile
  echo "ADD --chown=hadoop start-om.sh /opt/hadoop" >> Dockerfile

  docker build -t vvaks/hadoop-runner:ozone-0.4.0 .
  docker push vvaks/hadoop-runner:ozone-0.4.0
}

download_spark () {
  wget https://archive.apache.org/dist/spark/spark-2.4.0/spark-2.4.0-bin-without-hadoop.tgz
  tar -zxvf spark-2.4.0-bin-without-hadoop.tgz
}

build_spark_container () {
  download_spark
  cd spark-2.4.0-bin-without-hadoop

  bin/docker-image-tool.sh -r vvaks -t 2.4.0 build
  bin/docker-image-tool.sh -r vvaks -t 2.4.0 push

  cd ..
}

build_spark_hadoop_container () {

tee Dockerfile <<-'EOF'
FROM docker.io/vvaks/spark:2.4.0-0.0.0
RUN mkdir -p /opt/hadoop/conf
RUN mkdir /opt/ozone/

ADD hadoop/hadoop-dist/target/hadoop-3.3.0-SNAPSHOT /opt/hadoop/
ADD hadoop/hadoop-ozone/dist/target/ozone-0.4.0-SNAPSHOT /opt/ozone/

RUN cp /opt/hadoop/share/hadoop/hdfs/*.jar /opt/spark/jars/
RUN cp /opt/hadoop/share/hadoop/hdfs/lib/*.jar /opt/spark/jars/
RUN cp /opt/hadoop/share/hadoop/common/*.jar /opt/spark/jars/
RUN cp /opt/hadoop/share/hadoop/common/lib/*.jar /opt/spark/jars/
RUN cp /opt/hadoop/share/hadoop/mapreduce/*.jar /opt/spark/jars/
RUN cp /opt/hadoop/share/hadoop/yarn/*.jar /opt/spark/jars/
RUN cp /opt/hadoop/share/hadoop/yarn/lib/*.jar /opt/spark/jars/

ENV HADOOP_CONF_DIR=/opt/hadoop/conf
ENV SPARK_EXTRA_CLASSPATH=/opt/hadoop/conf:/opt/hadoop/share/hadoop/hdfs/*:/opt/hadoop/share/hadoop/hdfs/lib/*:/opt/hadoop/share/hadoop/yarn/*:/opt/hadoop/share/hadoop/yarn/lib/*:/opt/hadoop/share/hadoop/mapreduce/*:/opt/hadoop/share/hadoop/mapreduce/lib/*:/opt/ozone/share/ozone/lib/ratis-thirdparty-misc-0.2.0.jar:/opt/ozone/share/ozone/lib/ratis-proto-0.4.0-a8c4ca0-SNAPSHOT.jar:/opt/ozone/share/ozone/lib/hadoop-ozone-filesystem-0.4.0-SNAPSHOT.jar
EOF

  docker build -t vvaks/spark:2.4.0-3.3.0-SNAPSHOT .
  docker push vvaks/spark:2.4.0-3.3.0-SNAPSHOT
}

spark_inject_hadoop_jars () {
  yes | cp -f hadoop/hadoop-dist/target/hadoop-3.3.0-SNAPSHOT/share/hadoop/common/* spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-dist/target/hadoop-3.3.0-SNAPSHOT/share/hadoop/common/lib/* spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-dist/target/hadoop-3.3.0-SNAPSHOT/share/hadoop/hdfs/* spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-dist/target/hadoop-3.3.0-SNAPSHOT/share/hadoop/hdfs/lib/* spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-dist/target/hadoop-3.3.0-SNAPSHOT/share/hadoop/mapreduce/* spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-dist/target/hadoop-3.3.0-SNAPSHOT/share/hadoop/yarn/* spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-dist/target/hadoop-3.3.0-SNAPSHOT/share/hadoop/yarn/lib/* spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-ozone/dist/target/ozone-0.4.0-SNAPSHOT/share/ozone/lib/hadoop-ozone-filesystem-0.4.0-SNAPSHOT.jar spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-ozone/dist/target/ozone-0.4.0-SNAPSHOT/share/ozone/lib/ratis-thirdparty-misc-0.2.0.jar spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f hadoop/hadoop-ozone/dist/target/ozone-0.4.0-SNAPSHOT/share/ozone/lib/ratis-proto-0.4.0-f283ffa-SNAPSHOT.jar spark-2.4.0-bin-without-hadoop/jars/
}

spark_inject_jars_from_container () {
  docker create --name spark-temp vvaks/spark:2.4.0-3.3.0-SNAPSHOT
  docker cp spark-temp:/opt/spark/jars /tmp/spark-jars
  yes | cp /tmp/spark-jars/* spark-2.4.0-bin-without-hadoop/jars
  
  docker create --name ozone-temp vvaks/hadoop-runner:ozone-0.4.0
  docker cp ozone-temp:/opt/hadoop/share/ozone/lib /tmp/ozone-lib
  yes | cp -f /tmp/ozone-lib/hadoop-ozone-filesystem-0.4.0-SNAPSHOT.jar spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f /tmp/ozone-lib/ratis-thirdparty-misc-0.2.0.jar spark-2.4.0-bin-without-hadoop/jars/
  yes | cp -f /tmp/ozone-lib/ratis-proto-0.4.0-*-SNAPSHOT.jar spark-2.4.0-bin-without-hadoop/jars/
  
  docker rm spark-temp
  docker rm ozone-temp
}

deploy_ozone_k8s () {
  wget https://raw.githubusercontent.com/vakshorton/k8s-packages/master/ozone/resources/ozone-k8s-package.yaml
  kubectl create -f ozone-k8s-package.yaml
}

configure_aws_cli () {
  mkdir /root/.aws
  touch /root/.aws/credentials
  echo "[default]" >> /root/.aws/credentials
  echo "aws_access_key_id = $1" >> /root/.aws/credentials
  echo "aws_secret_access_key = $1" >> /root/.aws/credentials
  
  mkdir /home/centos/.aws
  cp /root/.aws/credentials /home/centos/.aws/credentials
  
  DATANODE_STATE=$(kubectl get pods datanode-0 -o wide -o json |grep phase)
  while [[ $DATANODE_STATE != *"Running"* ]]; do
    DATANODE_STATE=$(kubectl get pods datanode-0 -o wide -o json |grep phase)
    sleep 2
  done
  #aws s3api --endpoint-url http://$DATANODE0:30878 create-bucket --bucket=$2
}

install_utils
#build_hadoop
#build_ozone_container
download_spark
#build_spark_container
#build_spark_hadoop_container
#spark_inject_hadoop_jars
spark_inject_jars_from_container
deploy_ozone_k8s

export DATANODE0=$(kubectl get pods datanode-0 -o wide -o json|grep nodeName|grep -Po ': "[\S]+'|grep -Po '[^":,^\s]+')
export S3GATEWAY0=$(kubectl get pods datanode-0 -o wide -o json|grep nodeName|grep -Po ': "[\S]+'|grep -Po '[^":,^\s]+')
export OZONEMANAGER0=$(kubectl get pods ozonemanager-0 -o wide -o json|grep nodeName|grep -Po ': "[\S]+'|grep -Po '[^":,^\s]+')

echo "export DATANODE0=$DATANODE0" >> ~/.bash_profile
echo "export S3GATEWAY0=$S3GATEWAY0" >> ~/.bash_profile
echo "export OZONEMANAGER0=$OZONEMANAGER0" >> ~/.bash_profile
. ~/.bash_profile

configure_aws_cli "volume01"

tee README <<-'EOF'
********************************************************************************************************
EXECUTE BASH PROFILE TO ENSURE ENV VARS ARE LOADED
********************************************************************************************************
. ~/.bash_profile
********************************************************************************************************
CREATE OZONE BUCKET USING AWS CLI
********************************************************************************************************
aws s3api --endpoint-url http://$DATANODE0:30878 create-bucket --bucket=warehouse
********************************************************************************************************
DEMO SPARK ON K8S <--> OZONE
********************************************************************************************************
cd spark-2.4.0-bin-without-hadoop
bin/spark-shell \
--master k8s://https://$(hostname -f):6443 \
--conf spark.kubernetes.container.image=vvaks/spark:2.4.0-3.3.0-SNAPSHOT \
--conf spark.kubernetes.authenticate.driver.serviceAccountName=spark \
--conf spark.hadoop.fs.o3fs.impl=org.apache.hadoop.fs.ozone.OzoneFileSystem \
--conf spark.hadoop.ozone.om.address=$OZONEMANAGER0:30862 \
--conf spark.kubernetes.container.image.pullPolicy=Always
********************************************************************************************************
run the following at spark shell to simulate distributed read/write to Ozone using OzoneFileSystem client
********************************************************************************************************
sc.parallelize(Array(1,2,3,4,5)).saveAsTextFile("o3fs://warehouse.s3volume01/folder01")
spark.read.textFile("o3fs://warehouse.s3volume01/folder01").select("value").show
********************************************************************************************************
DEMO SPARK ON FROM EXTERNAL SPARK OUTSIDE OF K8S <--> OZONE S3GATEWAY
********************************************************************************************************
sudo yum install -y yum-utils device-mapper-persistent-data lvm2 epel-release
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install -y docker-ce jq wget git epel-release
sudo systemctl start docker
sudo docker create --name ozone-temp vvaks/hadoop-runner:ozone-0.4.0
sudo docker cp ozone-temp:/opt/hadoop/share/ozone/lib /tmp/ozone-lib
sudo -u hdfs haddop fs -chmod 777 /user
spark-shell \
--jars /tmp/ozone-lib/* \
--conf spark.hadoop.fs.s3a.endpoint=$DATANODE0:30878 \
--conf spark.hadoop.fs.s3a.access.key=volume01 \
--conf spark.hadoop.fs.s3a.secret.key=volume01 \
--conf spark.hadoop.fs.s3a.path.style.access=true \
--conf spark.hadoop.fs.s3a.connection.ssl.enabled=false
********************************************************************************************************
run the following at spark shell to simulate distributed read/write to Ozone using S3AFileSystem client
********************************************************************************************************
sc.parallelize(Array(1,2,3,4,5)).saveAsTextFile("s3a://warehouse/folder02")
spark.read.textFile("s3a://warehouse/folder02").select("value").show
********************************************************************************************************
EOF

#cp README /root

#from external cluster
#fs.s3a.endpoint=xxx:30878
#fs.s3a.access.key=volume01
#fs.s3a.secret.key=volume01
#fs.s3a.path.style.access=true
#fs.s3a.connection.ssl.enabled=false
#fs.o3fs.impl=org.apache.hadoop.fs.ozone.OzoneFileSystem