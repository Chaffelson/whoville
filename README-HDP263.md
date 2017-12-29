# Hortonworks HDP 2.6.3+ / HDF 3.0+ Simple Autodeployment

A set of quick deployment scripts and supporting artefacts to deploy Hortonworks HDP/HDF demo Sandboxes

##### To Deploy: New HDF3 install with HDF3 Example application: Streaming Trucking Demo
Status: Complete. Tested with build HDF3.0.0-453  

Create a Centos7 instance on AWS with at least 4cores/16GiB mem/25GiB disk  (recommend 8x32 for better experience)
ssh to the box and run:  
```bash
curl -sSL https://raw.githubusercontent.com/harshn08/whoville/master/deploy_generic_SAMTruckingDemo_fromscratch.sh | sudo -E bash
```

##### Demo walkthrough
Walkthrough available [here](http://community.hortonworks.com/articles/148015/partner-demo-kit-for-hdp-26hdf-30.html)
##### What is automated
- Ambari install
- HDF Mpack install
- HDP+HDF install
- Create demo artifacts:
  - Kafka topics for trucking
  - SR schemas for trucking
  - Nifi flow for trucking
  - SAM artifacts
  - SAM flow
  - Hbase/Phoenix tables
  - trucking simulator

##### What is not automated
- Supserset dashboard
  - This can be manually created using steps in [docs](https://docs.hortonworks.com/HDPDocuments/HDF3/HDF-3.0.3/bk_getting-started-with-stream-analytics/content/ch_sam-create-insights.html)

