#!/usr/bin/env bash

# Version: 0.3.0

sudo -i

exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>/var/log/cbd_bootstrap_centos7.log 2>&1


# Params
echo Exporting Params
export cb_ver=${cb_ver:-2.9.1}
export cbd_subdir=${cbd_subdir:-cbdeploy}
export cad_subdir=${cad_subdir:-cadeploy}
export cb_url=${cb_url:-public-repo-1.hortonworks.com/HDP/cloudbreak/cloudbreak-deployer_${cb_ver}_$(uname)_x86_64.tgz}
export cad_url=${cad_url:-http://archive.cloudera.com/director6/6.2/redhat7/cloudera-director.repo}
export uaa_secret=${uaa_secret:-VerySecretIndeed!}
export uaa_default_pw=${uaa_default_pw:-admin-password1}
export uaa_default_email=${uaa_default_email:-admin@example.com}
export public_ip=${public_ip:-$(curl -s icanhazptr.com)}

 # Install per Cloudbreak 2.7.2+
 # https://docs.hortonworks.com/HDPDocuments/Cloudbreak/Cloudbreak-2.7.1/content/aws-launch/index.html
echo Installing dependencies
yum clean metadata
yum clean all
yum install -y yum-utils
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum repolist
yum -y install net-tools ntp wget lsof unzip tar iptables-services sed device-mapper-persistent-data lvm2 docker-ce java-1.8.0-openjdk

# Environment Setup 
echo Modifying Environment Settings
systemctl enable ntpd
systemctl start ntpd
systemctl disable firewalld
systemctl stop firewalld
iptables --flush INPUT
iptables --flush FORWARD
service iptables save
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

systemctl start docker
systemctl enable docker

# Install Cloudera Director 6+
echo Installing Cloudera Director
wget ${cad_url} -O /etc/yum.repos.d/cloudera-director.repo
yum install -y cloudera-director-server cloudera-director-client

# Install Cloudbreak
echo Installing Cloudbreak
curl -Ls ${cb_url} | sudo tar -xz -C /bin cbd
cd /root && mkdir ${cbd_subdir} && cd ${cbd_subdir}
cat << EOF > Profile
export UAA_DEFAULT_SECRET=${uaa_secret}
export UAA_DEFAULT_USER_PW=${uaa_default_pw}
export UAA_DEFAULT_USER_EMAIL=${uaa_default_email}
export PUBLIC_IP=${public_ip}
export CB_MAX_SALT_RECIPE_EXECUTION_RETRY=180
EOF

# Startup

echo Configuring Cloudbreak
rm -f *.yml
cbd generate
cbd pull-parallel

echo Starting Cloudbreak
cbd start

echo Configuring Director
cd /opt && mkdir ${cad_subdir} && cd ${cad_subdir}
keytool -genkeypair -alias director -keyalg RSA \
  -keystore director.jks \
  -keysize 4096 -dname "CN=${public_ip},O=cloudera.com,ST=CA,C=US" \
  -storepass cloudera -keypass cloudera
sed -i "s/# lp.security.bootstrap.admin.password: admin/lp.security.bootstrap.admin.password: ${uaa_default_pw}/g" /etc/cloudera-director-server/application.properties
sed -i "s@# server.ssl.key-store:@server.ssl.key-store: /opt/${cad_subdir}/director.jks@g" /etc/cloudera-director-server/application.properties
sed -i "s/# server.ssl.key-store-password:/server.ssl.key-store-password: cloudera/g" /etc/cloudera-director-server/application.properties
# sed -i "s/# lp.bootstrap.packages.cmJavaPackages[1]/lp.bootstrap.packages.cmJavaPackages[1]/" /etc/cloudera-director-server/application.properties
# sed -i "s/# lp.bootstrap.packages.cmJavaPackages[0]/lp.bootstrap.packages.cmJavaPackages[0]/" /etc/cloudera-director-server/application.properties
# sed -i "s/oracle-j2sdk1.7/oracle-j2sdk1.8/" /etc/cloudera-director-server/application.properties
sed -i "s/# lp.normalization.required/lp.normalization.required/" /etc/cloudera-director-server/application.properties
# sed -i "s/# lp.bootstrap.packages/lp.bootstrap.packages/" /etc/cloudera-director-server/application.properties

echo Starting Cloudera Director
service cloudera-director-server start