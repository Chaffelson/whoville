#!/usr/bin/env bash

yum -y install iptables-services
yum -y install nfs-utils libseccomp lvm2 bridge-utils libtool-ltdl ebtables rsync policycoreutils-python 
yum -y install ntp bind-utils nmap-ncat openssl e2fsprogs redhat-lsb-core socat selinux-policy-base selinux-policy-targeted 

systemctl enable iptables
systemctl restart iptables
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

# set java_home on centos7
export JAVA_HOME=$(readlink -f /usr/bin/javac | sed "s:/bin/javac::") >> /etc/profile

sed -i "s@# End of file@*                soft    nofile         1048576\n*                hard    nofile         1048576\nroot             soft    nofile         1048576\nroot             hard    nofile         1048576\n# End of file@g" /etc/security/limits.conf

wget -q --no-check-certificate https://s3.eu-west-2.amazonaws.com/whoville/v2/temp.blob
mv temp.blob cloudera-data-science-workbench-1.5.0.818361-1.el7.centos.x86_64.rpm
yum install -y cloudera-data-science-workbench-1.5.0.818361-1.el7.centos.x86_64.rpm

cdsw init

