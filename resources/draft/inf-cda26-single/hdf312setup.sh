#!/usr/bin/env bash

export mpack_url=http://public-repo-1.hortonworks.com/HDF/centos7/3.x/updates/3.1.2.0/tars/hdf_ambari_mp/hdf-ambari-mpack-3.1.2.0-7.tar.gz

ambari-server install-mpack --verbose --mpack=${mpack_url}
ambari-server restart

# Update Base URL in Ambari