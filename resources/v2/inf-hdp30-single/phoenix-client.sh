#!/usr/bin/env bash

# Install Phoenix client
wget http://nexus-private.hortonworks.com/nexus/content/groups/public/org/apache/phoenix/phoenix-client/5.0.0.3.0.1.0-187/phoenix-client-5.0.0.3.0.1.0-187.jar
mkdir -p /usr/hdf/current/phoenix
chmod -R 755 /usr/hdf
cp phoenix-client-5.0.0.3.0.1.0-187.jar /usr/hdf/current/phoenix
chmod -R 777 /usr/hdf/current/phoenix