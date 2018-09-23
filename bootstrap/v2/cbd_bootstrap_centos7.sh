#!/usr/bin/env bash

sudo -i

exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>/var/log/cbd_bootstrap_centos7.log 2>&1


# Params
echo Exporting Params
export cbd_subdir=${cbd_subdir:-cbdeploy}
export cb_url=${cb_url:-public-repo-1.hortonworks.com/HDP/cloudbreak/cloudbreak-deployer_2.7.1_$(uname)_x86_64.tgz
export}
export uaa_secret=${uaa_secret:-VerySecretIndeed!}
export uaa_default_pw=${uaa_default_pw:-admin-password1}
export uaa_default_email=${uaa_default_email:-admin@example.com}
export public_ip=${public_ip:-$(curl -s icanhazptr.com)}

 # Install per Cloudbreak 2.7.1
 # https://docs.hortonworks.com/HDPDocuments/Cloudbreak/Cloudbreak-2.7.1/content/aws-launch/index.html
echo Patching local machine
yum -y update

echo Installing dependencies
yum -y install net-tools ntp wget lsof unzip tar iptables-services docker sed yq jq

# Environment Setup for Cloudbreak
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
sed -i 's/--log-driver=journald/--log-driver=json-file/g' /etc/sysconfig/docker
systemctl restart docker

echo Installing Cloudbreak
curl -Ls ${cb_url} | sudo tar -xz -C /bin cbd
rmdir -rf ${cbd_subdir} && mkdir ${cbd_subdir} && cd ${cbd_subdir}
cat << EOF > Profile
export UAA_DEFAULT_SECRET=${uaa_secret}
export UAA_DEFAULT_USER_PW=${uaa_default_pw}
export UAA_DEFAULT_USER_EMAIL=${uaa_default_email}
export PUBLIC_IP=${public_ip}
EOF

# Startup

echo Configuring Cloudbreak
rm -f *.yml
cbd generate
cbd pull-parallel

echo Starting Cloudbreak
cbd start
