#!/usr/bin/env bash

# WARNING: This script is only for RHEL7 on EC2

# Some of these installs may be unecessary but are included for completeness against documentation
yum -y install nfs-utils libseccomp lvm2 bridge-utils libtool-ltdl ebtables rsync policycoreutils-python ntp bind-utils nmap-ncat openssl e2fsprogs redhat-lsb-core socat selinux-policy-base selinux-policy-targeted 

# CDSW wants a pristine IPTables setup
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

# set java_home on centos7
export JAVA_HOME=$(readlink -f /usr/bin/javac | sed "s:/bin/javac::") >> /etc/profile

# Fetch public IP
export MASTER_IP=$(hostname --ip-address)

# Fetch public FQDN for Domain
export DOMAIN=$(curl https://icanhazptr.com)
export PUBLIC_IP='cdsw'.$(curl https://icanhazip.com)'.nip.io'

# unmount  vols - Cloudbreak will always mount presented volumes but this isn't a datanode
if lsblk | grep -q xvd ; then
    umount /dev/xvdb
    umount /dev/xvdc
    export DOCKER_BLOCK=/dev/xvdb
    export APP_BLOCK=/dev/xvdc
    sed -i '/hadoopfs/d' /etc/fstab
fi

if lsblk | grep -q nvme ; then
    echo "found NVME disks, processing"
    BLOCKS=$(lsblk | grep 500G | cut -d' ' -f1)
    for block in ${BLOCKS}; do
        echo "processing ${block}"
        umount /dev/${block}
        if [[ -z ${DOCKER_BLOCK+x} ]]; then
            echo "setting ${block} as DOCKER_BLOCK" 
            DOCKER_BLOCK=/dev/${block} 
        else
            echo "setting ${block} as APP_BLOCK"
            APP_BLOCK=/dev/${block}
            mkfs -t ext4 /dev/${block}
        fi
    done
    sed -i '/hadoopfs/d' /etc/fstab
fi

# Set limits
sed -i "s@# End of file@*                soft    nofile         1048576\n*                hard    nofile         1048576\nroot             soft    nofile         1048576\nroot             hard    nofile         1048576\n# End of file@g" /etc/security/limits.conf

# Install CDSW
wget -q --no-check-certificate https://s3.eu-west-2.amazonaws.com/whoville/v2/temp.blob
mv temp.blob cloudera-data-science-workbench-1.5.0.818361-1.el7.centos.x86_64.rpm
yum install -y cloudera-data-science-workbench-1.5.0.818361-1.el7.centos.x86_64.rpm

# Install Anaconda
curl -Ok https://repo.anaconda.com/archive/Anaconda2-5.2.0-Linux-x86_64.sh
chmod +x ./Anaconda2-5.2.0-Linux-x86_64.sh
./Anaconda2-5.2.0-Linux-x86_64.sh -b -p /anaconda

# CDSW Setup
sed -i "s@MASTER_IP=\"\"@MASTER_IP=\"${MASTER_IP}\"@g" /etc/cdsw/config/cdsw.conf
sed -i "s@JAVA_HOME=\"/usr/java/default\"@JAVA_HOME=\"$(echo ${JAVA_HOME})\"@g" /etc/cdsw/config/cdsw.conf
sed -i "s@DOMAIN=\"cdsw.company.com\"@DOMAIN=\"${PUBLIC_IP}\"@g" /etc/cdsw/config/cdsw.conf
sed -i "s@DOCKER_BLOCK_DEVICES=\"\"@DOCKER_BLOCK_DEVICES=\"${DOCKER_BLOCK}\"@g" /etc/cdsw/config/cdsw.conf
sed -i "s@APPLICATION_BLOCK_DEVICE=\"\"@APPLICATION_BLOCK_DEVICE=\"${APP_BLOCK}\"@g" /etc/cdsw/config/cdsw.conf
sed -i "s@DISTRO=\"\"@DISTRO=\"HDP\"@g" /etc/cdsw/config/cdsw.conf
sed -i "s@ANACONDA_DIR=\"\"@ANACONDA_DIR=\"/anaconda/bin\"@g" /etc/cdsw/config/cdsw.conf

# CDSW will break default Amazon DNS on 127.0.0.1:53, so we use a different IP
sed -i "s@nameserver 127.0.0.1@nameserver 169.254.169.253@g" /etc/dhcp/dhclient-enter-hooks

cdsw init

echo "CDSW will shortly be available on ${DOMAIN}"

exit 0