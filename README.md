# Hortonworks HDP 2.6.1+ / HDF 3.0+ Simple Autodeployment

A set of quick deployment scripts and supporting artefacts to deploy Hortonworks HDP/HDF vanilla Sandboxes

##### To Deploy: New HDF3 install on an AWS Instance
Status: Complete. Tested with build HDF3.0.0-453  

Create a Centos7 instance on AWS with at least 4cores/16GiB mem/25GiB disk  (recommend 8x32 for better experience)
ssh to the box and run:  
```bash
curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/deploy_AWS.sh | sudo -E sh
```

##### To Deploy: HDF3 Example application: Streaming Trucking Demo
Status: Incomplete but working. Tested with build HDF3.0.0-453

1.  connect to your whoville box 
2.  start all services
3.  run the following in bash prompt:
```bash
curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/deploy_SAMTruckingDemo.sh | sudo -E sh
```

##### To Deploy: A public AMI Centos base image
Note: This may be useful if you intend to create a public AMI of your demo/image
1.  Get the base Centos7 x64 image in your region from https://wiki.centos.org/Cloud/AWS e.g eu-west-2 ami-c22236a6
2.  Launch a copy of that AMI on your account
3.  ssh centos@'[FQDN]'  
```bash
sudo yum update -y
sudo shutdown now
```
4.  Create base AMI
5.  Power up Instance again and install and prepare your business
6.  You probably want to clean up the VM for imaging:
```bash
curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/image_prepare.sh | sudo -E sh
```
7.  Create AMI. Make it Public. Bask in your popularity.
