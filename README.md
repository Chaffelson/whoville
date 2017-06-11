# Hortonworks HDF 3.0 Simple Autodeployment

### Description
A set of quick deployment scripts and supporting artefacts to deploy Hortonworks whoville's: HDP/HDF vanilla Sandboxes

##### To Deploy: New HDF3 Sandbox on an AWS Instance
Status: Complete. Tested with build HDF3.0.0-453  

Create a Centos7 instance on AWS with at least 4cores/16GiB mem/25GiB disk  
ssh to the box and run:  
```bash
curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/deploy_AWS.sh | sudo -E sh
```

##### To Deploy: HDF3 Example application: Streaming Trucking Demo
Status: Incomplete but working. Tested with build HDF3.0.0-453

ssh to your HDF3 Sandbox and run:
```bash
curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/deploy_SAMTruckingDemo.sh | sudo -E sh
```

##### To Deploy: 
Note: This may be useful if you intend to create a public AMI of your demo/image
1.  Get the base Centos7 x64 image in your region from https://wiki.centos.org/Cloud/AWS e.g eu-west-2 ami-c22236a6
2.  Launch a copy of that AMI on your account
3.  ssh centos@'[FQDN]'  
```bash
sudo yum update -y
sudo shutdown now
```
4.  Create base AMI
5.  Power up Instance again and continue