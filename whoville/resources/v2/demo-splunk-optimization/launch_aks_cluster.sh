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
pip install awscli --upgrade --user

aws ec2 describe-subnets --filters Name=tag:Name,Values=$PREFIX"whoville" --region $REGION > subnets.json

# Create additional subnet if needed
num_subnets=$(jq '.Subnets[].SubnetId' subnets.json | wc -l)
if [ $((num_subnets + 0)) -eq 1 ] 
then 
   # Setting Availability zone to original region + b 
   sub_1_az=$(jq '.Subnets[0].AvailabilityZone' subnets.json |  sed -r 's/\"//g')
   sub_2_az=$(echo ${sub_1_az::-1}b)

   # Setting CIDR block to x.x.99.x/y
   sub_1_cidr=$(jq '.Subnets[0].CidrBlock' subnets.json |  sed -r 's/\"//g')
   sub_2_cidr=$(echo $sub_1_cidr | awk -F "." '{print $1"."$2".99."$4}')

   # Getting the VPC ID
   sub_1_vpc_id=$(jq '.Subnets[0].VpcId' subnets.json |  sed -r 's/\"//g')

   aws ec2 create-subnet --availability-zone $sub_2_az --cidr-block $sub_2_cidr --vpc-id $sub_1_vpc_id --region $REGION > new_subnet.json
   new_subnet_id=$(jq '.Subnet.SubnetId' new_subnet.json |  sed -r 's/\"//g')
   aws ec2 create-tags --resources $new_subnet_id --tags Key=Name,Value=$PREFIX"whoville" --region $REGION
   aws ec2 describe-subnets --filters Name=tag:Name,Values=$PREFIX"whoville" --region $REGION > subnets.json
fi 


# Getting subnets ids
sub_id_1=$(jq '.Subnets[0].SubnetId' subnets.json |  sed -r 's/\"//g')
sub_id_2=$(jq '.Subnets[1].SubnetId' subnets.json |  sed -r 's/\"//g')

# Launching aks


eksctl create cluster \
--name $PREFIX"k8s" \
--version 1.13 \
--nodegroup-name standard-workers \
--node-type t3.medium \
--nodes 3 \
--nodes-min 1 \
--nodes-max 4 \
--vpc-public-subnets=$sub_id_1,$sub_id_2 \
--node-ami auto \
--region $REGION

# launches minifi

kubectl apply -f /home/nifi/minifi-k8s/minifi.yml

# adds autoscale

kubectl autoscale deployment minifi --cpu-percent=25 --min=1 --max=3


