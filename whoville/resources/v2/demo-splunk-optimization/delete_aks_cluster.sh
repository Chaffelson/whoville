#!/bin/sh

display_usage() { 
	echo "
Usage:
    $(basename "$0") <AWS_ACCESS_KEY_ID> <AWS_SECRET_ACCESS_KEY> <AWS_REGION> <WHOVILLE_PREFIX> [MINIFI_DEPLOYMENT_FILE] [--help or -h]

Description:
    Launches an aks cluster ready wand a minifi deployment on it.

Arguments:
    AWS_ACCESS_KEY_ID:  Your AWS KEY ID, e.g. AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY: Your AWS_SECRET_ACCESS_KEY, e.g. wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    AWS_REGION: Your AWS_REGION, e.g. us-east-1
    WHOVILLE_PREFIX: Your whoville prefix, e.g. pvi-
    MINIFI_DEPLOYMENT_FILE (optional): Location of your deployment file, default (already created by whoville deployment): /home/nifi/minifi-k8s/minifi.yml
    --help or -h:   displays this help"

}
# check whether user had supplied -h or --help . If yes display usage 
if [[ ( $1 == "--help") ||  $1 == "-h" ]] 
then 
    display_usage
    exit 0
fi 


# Check the numbers of arguments
if [  $# -lt 4 ] 
then 
    echo "Not enough arguments!"
    display_usage
    exit 1
fi 

if [  $# -gt 5 ] 
then 
    echo "Too many arguments!"
    display_usage
    exit 1
fi 

if [  $# -eq 4 ] 
then 
    export MINIFI_DEPLOYMENT_FILE=/home/nifi/minifi-k8s/minifi.yml
fi 

if [  $# -eq 5 ] 
then 
    export MINIFI_DEPLOYMENT_FILE=$5
fi 


# Export AWS creds

export AWS_ACCESS_KEY_ID=$1
export AWS_SECRET_ACCESS_KEY=$2
export REGION=$3
export PREFIX=$4

# deletes minifi

kubectl delete -f /home/nifi/minifi-k8s/minifi.yml

# deletes autoscale

kubectl delete horizontalpodautoscaler.autoscaling/minifi

# deletes cluster

eksctl delete cluster --name=$PREFIX"k8s"


