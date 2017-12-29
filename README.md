# Hortonworks HDP 2.6.3+ / HDF 3.0+ Simple Autodeployment

A set of quick deployment scripts and supporting artefacts to deploy Hortonworks HDP/HDF demo Sandboxes

##### To Deploy: New HDF3 install with HDF3 Example application: Streaming Trucking Demo
Status: Tested with build HDP 2.6.3 / Ambari 2.5.1 / HDF mpack 3.0.1.1-5

- Pre-reqs:
  - Launch a single vanilla Centos/RHEL 7.x VM (e.g. on local VM or openstack or cloud provider of choice) 
  - The VM should not already have any Ambari or HDP components installed (e.g. do NOT run script on HDP sandbox)
  - The VM requires 4 vcpus and ~17-18 GB RAM once all services are running and you execute a query, so m3.2xlarge size is recommended
  

- Login to the instance and run:  
```bash
curl -sSL https://raw.githubusercontent.com/harshn08/whoville/master/deploy_generic_SAMTruckingDemo_fromscratch.sh | sudo -E bash
```

Once the script completes (about 30min), you can start reviewing the Registry, NiFi, SAM, Storm UIs. However, you will need to wait for additional 20-30min for Druid to index the data before you can start creating Superset dashboards against the Druid cubes.

##### Login details 
- Ambari port: 8080 login: admin/StrongPassword
- Supserset port: 9089 login: admin/StrongPassword

##### Demo walkthrough
Detailed walkthrough available [here](http://community.hortonworks.com/articles/148015/partner-demo-kit-for-hdp-26hdf-30.html)

##### What is automated
- [x] Ambari install
- [x] HDF Mpack install
- [x] HDP+HDF install
- [x] Create demo artifacts:
  - [x] Kafka topics for trucking
  - [x] SR schemas for trucking
  - [x] Nifi flow for trucking
  - [x] SAM artifacts
  - [x] SAM flow
  - [x] Hbase/Phoenix tables
  - [x] Trucking simulator

##### What is not automated
- [ ] Import of Supserset dashboard
  - This can be manually created using steps in [docs](https://docs.hortonworks.com/HDPDocuments/HDF3/HDF-3.0.3/bk_getting-started-with-stream-analytics/content/ch_sam-create-insights.html)

###### Older versions
Previous README available [here](https://github.com/harshn08/whoville/blob/master/README-HDP261.md)
