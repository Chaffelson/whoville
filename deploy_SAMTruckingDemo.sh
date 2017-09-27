#!/usr/bin/env bash
# Only tested on Centos7 SingleNode deployments
# Schema Registry Swagger docco: http://localhost:7788/api/swagger#/
# #!
# OS Setup
sudo yum install -y jq xml2
# Download schemas
curl -ssLO https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/schema_rawTruckEvents.avsc
curl -ssLO https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/schema_geoTruckEvents.avsc
curl -ssLO https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/schema_TruckSpeedEvents.avsc
# Create Schemas in Registry
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "raw-truck_events_avro", "description": "Raw Geo events from trucks in Kafka Topic", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "raw-truck_speed_events_avro", "description": "Raw Speed Events from trucks in Kafka Topic", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "truck_events_avro", "description": "Schema for the kafka topic named truck_events_avro", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "truck_speed_events_avro", "description": "Schema for the kafka topic named truck_speed_events_avro", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
# Upload schemas to registry
curl -X POST -F 'name=raw-truck_events_avro' -F 'description=ver1' -F 'file=@./schema_rawTruckEvents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/raw-truck_events_avro/versions/upload
curl -X POST -F 'name=raw-truck_speed_events_avro' -F 'description=ver1' -F 'file=@./schema_TruckSpeedEvents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/raw-truck_speed_events_avro/versions/upload
curl -X POST -F 'name=truck_events_avro' -F 'description=ver1' -F 'file=@./schema_geoTruckEvents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/truck_events_avro/versions/upload
curl -X POST -F 'name=truck_speed_events_avro' -F 'description=ver1' -F 'file=@./schema_TruckSpeedEvents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/truck_speed_events_avro/versions/upload
# Kafka
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partition 1 --topic raw-truck_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partition 1 --topic raw-truck_speed_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partition 1 --topic truck_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partition 1 --topic truck_speed_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --zookeeper localhost:2181 --list
# NiFi Template Download
curl -ssLO https://raw.githubusercontent.com/Chaffelson/whoville/master/templates/nifiTemplate_SAMTruckingDemo.xml
# Get root PG ID
curl -sX GET http://$(hostname -f):9090/nifi-api/process-groups/root > rootPG.json
rootpgid=$(jq -r '.id' ./rootPG.json)
# Push the template to NiFi
curl -F template=@nifiTemplate_SAMTruckingDemo.xml -X POST  http://$(hostname -f):9090/nifi-api/process-groups/$rootpgid/templates/upload > templateResp.xml
# Get the template ID out of the response
templateid=$(xml2 < templateResp.xml | sed -n 's/.*id=//p')


# Oustanding Manual Steps for users
# Deploy and start NiFi Template
# Deploy and Start SAM Topology
# Create Superset Dashboard
