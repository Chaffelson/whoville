#!/bin/bash

# legacy Python2 install process, deprecated as numpy now requires py3.5+
#yum install -y epel-release
#yum install -y python-pip

# Install python 3.5 for numpy 1.17+
yum -yq install @development rh-python35
source /opt/rh/rh-python35/enable
export PYTHONHOME=/opt/rh/rh-python35/root/usr/
export PYTHONPATH=/opt/rh/rh-python35/root/usr/lib64/python3.5
pip install --upgrade pip
pip install numpy