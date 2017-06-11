#!/usr/bin/env bash
# Only tested on Centos7 SingleNode deployments
# Schema Registry Swagger docco: http://localhost:7788/api/swagger#/
# #!
# OS Setup
sudo yum install -y jq xml2
# Download schemas
curl -ssLO https://gist.githubusercontent.com/Chaffelson/2b7801007f65a10b13cf5690b6921eb6/raw/06e986f22f1c384a2d9c3c2d6b45f9c1b1f4c052/rawtruckevents.avsc
curl -ssLO https://gist.githubusercontent.com/Chaffelson/0e8f90ab153ea19295b6992b7512307e/raw/8cae7efd1115c2e1d6862e40959d9c924ff7615e/geotruckevents.avsc
curl -ssLO https://gist.githubusercontent.com/Chaffelson/5b757ee6db17f5a0947facf530a4d429/raw/94aa12eb6f5180d6f76e69d3e7afb1c2d91c8c72/truckspeedevents.avsc
# Create Schemas in Registry
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "raw-truck_events_avro", "description": "Raw Geo events from trucks in Kafka Topic", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "raw-truck_speed_events_avro", "description": "Raw Speed Events from trucks in Kafka Topic", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "truck_events_avro", "description": "Schema for the kafka topic named truck_events_avro", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
curl -H "Content-Type: application/json" -X POST -d '{ "type": "avro", "schemaGroup": "truck-sensors-kafka", "name": "truck_speed_events_avro", "description": "Schema for the kafka topic named truck_speed_events_avro", "compatibility": "BACKWARD", "evolve": true}' http://localhost:7788/api/v1/schemaregistry/schemas
# Upload schemas to registry
curl -X POST -F 'name=raw-truck_events_avro' -F 'description=ver1' -F 'file=@./rawtruckevents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/raw-truck_events_avro/versions/upload
curl -X POST -F 'name=raw-truck_speed_events_avro' -F 'description=ver1' -F 'file=@./truckspeedevents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/raw-truck_speed_events_avro/versions/upload
curl -X POST -F 'name=truck_events_avro' -F 'description=ver1' -F 'file=@./geotruckevents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/truck_events_avro/versions/upload
curl -X POST -F 'name=truck_speed_events_avro' -F 'description=ver1' -F 'file=@./truckspeedevents.avsc' http://localhost:7788/api/v1/schemaregistry/schemas/truck_speed_events_avro/versions/upload
# Kafka
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partition 1 --topic raw-truck_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partition 1 --topic raw-truck_speed_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partition 1 --topic truck_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partition 1 --topic truck_speed_events_avro
/usr/hdp/current/kafka-broker/bin/kafka-topics.sh --zookeeper localhost:2181 --list
# NiFi Template Upload
curl -ssLO https://gist.githubusercontent.com/Chaffelson/9134de6da521755e8863d4ab8864f784/raw/90028732751e1f033b249fba5c4ae6404f105827/NiFiSamTemplate.xml
curl -sX GET http://$(hostname -f):9090/nifi-api/process-groups/root > rootPG.json
rootpgid=$(jq -r '.id' ./rootPG.json)
curl -F template=@NiFiSamTemplate.xml -X POST  http://$(hostname -f):9090/nifi-api/process-groups/$rootpgid/templates/upload > templateResp.xml
templateid=$(xml2 < templateResp.xml | sed -n 's/.*id=//p')


# Oustanding Manual Steps for users
# Deploy and start NiFi Template
# Deploy and Start SAM Topology
# Create Superset Dashboard