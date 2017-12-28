# Register a service pool cluster
curl -H 'content-type: application/json' http://${host}:7777/api/v1/catalog/clusters -d @- <<EOF
{"name":"${cluster_name}","description":"Registering Cluster : ${cluster_name}","ambariImportUrl":"http://${host}:8080/api/v1/clusters/${cluster_name}"}
EOF

# Import cluster services with Ambari
curl -H 'content-type: application/json' http://${host}:7777/api/v1/catalog/cluster/import/ambari -d @- <<EOF
{"clusterId":1,"ambariRestApiRootUrl":"http://${host}:8080/api/v1/clusters/${cluster_name}","username":"admin","password":"${ambari_password}"}
EOF

# Create namespace/environment
curl -H 'content-type: application/json' http://${host}:7777/api/v1/catalog/namespaces -d @- <<EOF
{"name":"TruckingDemo","description":"Trucking Environment","streamingEngine":"STORM"}
EOF

# Add services to environment
curl -H 'content-type: application/json' http://${host}:7777/api/v1/catalog/namespaces/1/mapping/bulk -d @- <<EOF
[{"clusterId":1,"serviceName":"KAFKA","namespaceId":1},{"clusterId":1,"serviceName":"DRUID","namespaceId":1},{"clusterId":1,"serviceName":"STORM","namespaceId":1},{"clusterId":1,"serviceName":"HDFS","namespaceId":1},{"clusterId":1,"serviceName":"HDFS","namespaceId":1},{"clusterId":1,"serviceName":"HBASE","namespaceId":1},{"clusterId":1,"serviceName":"ZOOKEEPER","namespaceId":1}]
EOF

#Adding the SAM extension Dependencies ie Custom udf and processors
cd
export cwd=$(pwd)
git clone https://github.com/harshn08/whoville.git
curl -F udfJarFile=@$cwd/whoville/SAMExtensions/sam-custom-udf-0.0.5.jar -F 'udfConfig={"name":"TIMESTAMP_LONG","displayName":"TIMESTAMP_LONG","description":"Converts a String timestamp to Timestamp Long","type":"FUNCTION","className":"hortonworks.hdf.sam.custom.udf.time.ConvertToTimestampLong"};type=application/json' -X POST http://${host}:7777/api/v1/catalog/streams/udfs
curl -F udfJarFile=@$cwd/whoville/SAMExtensions/sam-custom-udf-0.0.5.jar -F 'udfConfig={"name":"GET_WEEK","displayName":"GET_WEEK","description":"For a given data time string, returns week of the input date","type":"FUNCTION","className":"hortonworks.hdf.sam.custom.udf.time.GetWeek"};type=application/json' -X POST http://${host}:7777/api/v1/catalog/streams/udfs
curl -F udfJarFile=@$cwd/whoville/SAMExtensions/sam-custom-udf-0.0.5.jar -F 'udfConfig={"name":"ROUND","displayName":"ROUND","description":"Rounds a double to an integer","type":"FUNCTION","className":"hortonworks.hdf.sam.custom.udf.math.Round"};type=application/json' -X POST http://${host}:7777/api/v1/catalog/streams/udfs

curl -sS -X POST -i -F jarFile=@$cwd/whoville/SAMExtensions/sam-custom-processor-0.0.5-jar-with-dependencies.jar http://${host}:7777/api/v1/catalog/streams/componentbundles/PROCESSOR/custom -F customProcessorInfo=@$cwd/whoville/SAMExtensions/phoenix-enrich-truck-demo.json
curl -sS -X POST -i -F jarFile=@$cwd/whoville/SAMExtensions/sam-custom-processor-0.0.5.jar http://${host}:7777/api/v1/catalog/streams/componentbundles/PROCESSOR/custom -F customProcessorInfo=@$cwd/whoville/SAMExtensions/enrich-weather.json
curl -sS -X POST -i -F jarFile=@$cwd/whoville/SAMExtensions/sam-custom-processor-0.0.5a.jar http://${host}:7777/api/v1/catalog/streams/componentbundles/PROCESSOR/custom -F customProcessorInfo=@$cwd/whoville/SAMExtensions/normalize-model-features.json

#import topology to SAM
curl -F file=@$cwd/whoville/topology/truckingapp.json -F topologyName=TruckingDemo -F namespaceId=1 -X POST http://${host}:7777/api/v1/catalog/topologies/actions/import
