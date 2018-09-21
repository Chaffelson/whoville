# This script explicitly run the data simulator

# setting up data simulator directory
export DATA_SIMULATOR=/tmp/whoville/data_simulator

nohup java -cp $DATA_SIMULATOR/stream-simulator-jar-with-dependencies.jar \
hortonworks.hdp.refapp.trucking.simulator.SimulationRegistrySerializerRunnerApp \
20000 \
hortonworks.hdp.refapp.trucking.simulator.impl.domain.transport.Truck \
hortonworks.hdp.refapp.trucking.simulator.impl.collectors.KafkaEventSerializedWithRegistryCollector \
1 \
$DATA_SIMULATOR/routes/midwest/ \
10000 \
$(hostname -f):6667 \
http://$(hostname -f):7788/api/v1 \
ALL_STREAMS \
NONSECURE  &
