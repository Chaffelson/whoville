#!/usr/bin/env bash

setenforce 0
sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
modprobe br_netfilter
echo '1' > /proc/sys/net/bridge/bridge-nf-call-iptables
swapoff -a

echo "/dev/mapper/centos-swap swap swap defaults 0 0" >> /etc/fstab

yum install -y yum-utils device-mapper-persistent-data lvm2 epel-release
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install -y docker-ce jq wget git epel-release
dhclient

systemctl start docker
systemctl enable docker

cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg
        https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF

yum install -y kubelet kubeadm kubectl

cat <<EOF > /tmp/prepare-k8s-service.sh
#!/bin/bash
#systemctl start kubelet
#systemctl enable kubelet

#sed -i 's/cgroup-driver=systemd/cgroup-driver=cgroupfs/g' /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
#systemctl daemon-reload
#systemctl restart kubelet

sudo echo "KUBELET_EXTRA_ARGS=--cgroup-driver=cgroupfs --runtime-cgroups=/systemd/system.slice --kubelet-cgroups=/systemd/system.slice" > /etc/sysconfig/kubelet

EOF
chmod 755 /tmp/prepare-k8s-service.sh

cat <<EOF > /tmp/initialize-k8s-cluster.sh
#!/bin/bash

#sudo kubeadm init --apiserver-advertise-address=$(ifconfig eth0|grep -Po 'inet [0-9.]+'|grep -Po '[0-9.]+') --pod-network-cidr=10.244.0.0/16 > /tmp/k8s-init.log

mkdir -p ~/.kube
sudo cp -if /etc/kubernetes/admin.conf ~/.kube/config
sudo cp -if /etc/kubernetes/admin.conf /root/.kube/config
sudo chown centos:centos ~/.kube/config

kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml

curl https://raw.githubusercontent.com/helm/helm/master/scripts/get | bash -s -- -v v2.10.0
helm init

EOF
chmod 755 /tmp/initialize-k8s-cluster.sh

echo "complete" > /tmp/status.success

reboot