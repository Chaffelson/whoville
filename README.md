# Hortonworks HDF 3.0 Simple Autodeployment

### Description
A set of quick deployment scripts and supporting artefacts to deploy Hortonworks HDF3 vanilla Sandboxes

### Quickstart
##### To Deploy: New HDF3 Sandbox on an AWS Instance
Status: Complete. Tested with build HDF3.0.0-453  

Create a Centos7 instance on AWS with at least 4cores/16GiB mem/25GiB disk  
ssh to the box and run:  
```bash
curl -sSL https://raw.githubusercontent.com/Chaffelson/AutoHDF/master/deploy_AWS-Centos7.sh | sudo -E sh
```

##### To Deploy: HDF3 Example application: Streaming Trucking Demo
Status: Incomplete but working. Tested with build HDF3.0.0-453

ssh to your HDF3 Sandbox and run:
```bash
curl -sSL https://raw.githubusercontent.com/Chaffelson/AutoHDF/master/deploy_SAMTruckingDemo.sh | sudo -E sh
```
