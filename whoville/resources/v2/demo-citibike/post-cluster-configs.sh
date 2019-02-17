#!/bin/bash

# Install Anaconda
yum install -y bzip2
wget https://repo.continuum.io/archive/Anaconda2-4.3.1-Linux-x86_64.sh
bash ./Anaconda2-4.3.1-Linux-x86_64.sh -b -p /opt/anaconda

# Instantiate NiFi template
tee /root/instantiate_nifi.py <<-'EOF'
import nipyapi
import tempfile
import requests
import os
import socket

hostname = socket.gethostname()
nipyapi.config.nifi_config.host = 'http://' + hostname + ':9092/nifi-api'

t = 'https://s3.eu-west-2.amazonaws.com/whoville/v1/t4hackathon_v1.xml'

# Download template
content = requests.get(t).content

# write into temporary file
tf_handle, tf_name = tempfile.mkstemp()
os.write(tf_handle, content)
os.close(tf_handle)

# Upload to NiFi
# The default implementation requires the template is uploaded from file
template = nipyapi.templates.upload_template(
    nipyapi.canvas.get_root_pg_id(),
    tf_name,
)

# Instantiate template
nipyapi.templates.deploy_template(
    nipyapi.canvas.get_root_pg_id(),
    template.id
)
EOF
chmod +x /root/instantiate_nifi.py

virtualenv nipyapi
source nipyapi/bin/activate
pip install nipyapi
python /root/instantiate_nifi.py
