# -*- coding: utf-8 -*-

"""
For interactions with Deployment Infrastructure

Warnings:
    Experimental, not extensively tested
"""

from __future__ import absolute_import
import logging
import requests
import socket
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.common.exceptions import BaseHTTPError
import boto3
from whoville import config, utils, security

__all__ = ['create_libcloud_session', 'create_boto3_session', 'get_cloudbreak',
           'create_cloudbreak', 'add_sec_rule_to_ec2_group', 'deploy_node',
           'create_node', 'list_images', 'list_sizes', 'list_networks',
           'list_subnets', 'list_security_groups', 'list_keypairs',
           'list_nodes']

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

namespace = config.profile['namespace']
namespace = namespace if namespace else ''


def create_libcloud_session(provider='EC2'):
    cls = get_driver(getattr(Provider, provider))
    params = config.profile.get('platform')
    if not params:
        raise ValueError("Profile not configured with Platform Parameters")
    return cls(
        **{x: y for x, y in params.items()
           if x in ['key', 'secret', 'region']}
    )


def create_boto3_session():
    platform = config.profile.get('platform')
    if platform['provider'] == 'EC2':
        return boto3.Session(
            aws_access_key_id=platform['key'],
            aws_secret_access_key=platform['secret'],
            region_name=platform['region']
        )
    else:
        raise ValueError("EC2 infra access keys not defined in Profile")


def get_cloudbreak(s_libc=None, create=True, purge=False):
    if not s_libc:
        s_libc = create_libcloud_session()
    
    cbd_name = namespace + 'cloudbreak'
    cbd = list_nodes(s_libc, {'name': cbd_name})
    cbd = [x for x in cbd if x.state != 'terminated']
    if cbd:
        if not purge:
            log.info("Cloudbreak [%s] found, returning instance",
                     cbd[0].name)
            return cbd[0]
        else:
            log.info("Cloudbreak found, Purge is True, destroying...")
            [s_libc.destroy_node(x) for x in cbd]
            cbd = None
    if not cbd:
        log.info("Cloudbreak instance [%s] not found", cbd_name)
        if not create:
            log.info("Cloudbreak not found, Create is False, returning None")
            return None
        else:
            log.info("Cloudbreak is None, Create is True - deploying new "
                     "Cloudbreak [%s]", cbd_name)
            cbd = create_cloudbreak(s_libc, cbd_name)
            log.info("Waiting for Cloudbreak Deployment to Complete")
            public_dns_name = str(socket.gethostbyaddr(cbd.public_ips[0])[0])
            utils.wait_to_complete(
                utils.is_endpoint_up,
                'https://' + public_dns_name,
                whoville_delay=30,
                whoville_max_wait=600
            )
            return cbd


def create_cloudbreak(session, cbd_name):
    s_boto3 = create_boto3_session()
    client_cf = s_boto3.client('cloudformation')
    cf_stacks = client_cf.list_stacks()
    log.info("Looking for existing Cloud Formation stacks within namespace: " + namespace)
    for cf_stack in cf_stacks['StackSummaries']:
        if namespace in cf_stack['StackName']:
            log.info("Found Cloud Formation "+cf_stack['StackName']+", deleting to avoid collision with Cloudbreak cluster creation...")
            client_cf.delete_stack(StackName=cf_stack['StackName'])
    
    public_ip = requests.get('http://icanhazip.com').text.rstrip()
    net_rules = [
        {
            'protocol': 'tcp',
            'from_port': 9443,
            'to_port': 9443,
            'cidr_ips': ['0.0.0.0/0']
        },
        {
            'protocol': -1,
            'from_port': 1,
            'to_port': 65535,
            'cidr_ips': [public_ip + '/32']
        },
        {
            'protocol': 'tcp',
            'from_port': 443,
            'to_port': 443,
            'cidr_ips': ['0.0.0.0/0']
        },
        {
            'protocol': 'tcp',
            'from_port': 22,
            'to_port': 22,
            'cidr_ips': ['0.0.0.0/0']
        }
    ]
    if session.type == 'ec2':
        images = list_images(
            session,
            filters={
                'name': '*CentOS Linux 7 x86_64 HVM EBS ENA*',
            }
        )
        image = sorted(images, key=lambda k: k.extra['description'][-7:])
        if not image:
            raise ValueError("Couldn't find a valid Centos7 Image")
        else:
            image = image[-1]
        bd = image.extra['block_device_mapping'][0]
        root_vol = {
            'VirtualName': None,
            'DeviceName': bd['device_name'],
            'Ebs': {
                'VolumeSize': 50,
                'VolumeType': bd['ebs']['volume_type'],
                'DeleteOnTermination': True
            }
        }
        machines = list_sizes(
            session, cpu_min=4, cpu_max=4, mem_min=16000, mem_max=20000
        )
        if not machines:
            raise ValueError("Couldn't find a VM of the right size")
        else:
            machine = machines[-1]
        networks = list_networks(session)
        network = sorted(networks, key=lambda k: k.extra['is_default'])
        if not network:
            raise ValueError("There should be at least one network, this "
                             "is rather unexpected")
        else:
            network = network[-1]
        subnets = list_subnets(session, {'extra.vpc_id': network.id})
        subnet = sorted(subnets, key=lambda k: k.state)
        if not subnet:
            raise ValueError("Expecting at least one subnet on a network")
        else:
            subnet = subnet[0]
        sec_group = list_security_groups(session, {'name': namespace})
        if not sec_group:
            _ = session.ex_create_security_group(
                name=namespace + 'whoville-default',
                description=namespace + 'whoville-default Security Group',
                vpc_id=network.id
            )
            sec_group = list_security_groups(session, {'name': namespace})[-1]
        else:
            sec_group = sec_group[-1]
        net_rules.append(
            {
                'protocol': -1,
                'group_pairs': [{'group_id': sec_group.id}],
                'from_port': 0,
                'to_port': 0
            }
        )
        for rule in net_rules:
            add_sec_rule_to_ec2_group(session, rule, sec_group.id)
        ssh_key = list_keypairs(
            session, {'name': config.profile['sshkey_name']}
        )
        if not ssh_key:
            ssh_key = session.import_key_pair_from_string(
                name=config.profile['sshkey_name'],
                key_material=config.profile['sshkey_pub']
            )
        else:
            ssh_key = [x for x in ssh_key
                       if x.name == config.profile['sshkey_name']][0]
        # https://goo.gl/UddnF9 redirects to:
        # https://raw.githubusercontent.com/Chaffelson/whoville/hdp3cbd/
        # bootstrap/v2/cbd_bootstrap_centos7.sh
        # This is just more tidy
        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "export uaa_secret=" + security.get_secret('masterkey'),
            "export uaa_default_pw=" + security.get_secret('password'),
            "export uaa_default_email=" + config.profile['email'],
            "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
            "/whoville/master/bootstrap/v2/cbd_bootstrap_centos7.sh)"
        ]
        script = '\n'.join(script_lines)
        cbd = create_node(
            session=session,
            name=cbd_name,
            image=image,
            machine=machine,
            params={
                'ex_security_group_ids': [sec_group.id],
                'ex_subnet': subnet,
                'ex_assign_public_ip': True,
                'ex_blockdevicemappings': [root_vol],
                'ex_keyname': ssh_key.name,
                'ex_userdata': script
            }
        )
        log.info("Waiting for Cloudbreak Instance to be Available...")
        session.wait_until_running(nodes=[cbd])
        log.info("Cloudbreak Infra Booted at [%s]", cbd)
        log.info("Assigning Static IP to Cloudbreak")
        static_ips = [x for x in session.ex_describe_all_addresses()
                      if x.instance_id is None]
        if not static_ips:
            static_ip = session.ex_allocate_address()
        else:
            static_ip = static_ips[0]
        if not static_ip:
            raise ValueError("Couldn't get a Static IP for Cloudbreak")
        session.ex_associate_address_with_node(cbd, static_ip)
        # Assign Role ARN
        s_boto3 = create_boto3_session()
        client = s_boto3.client('ec2')
        infra_arn = config.profile['platform']['infraarn']
        client.associate_iam_instance_profile(
            IamInstanceProfile={
                'Arn': infra_arn,
                'Name': infra_arn.rsplit('/')[-1]
            },
            InstanceId=cbd.id
        )
        # get updated node information
        cbd = list_nodes(session, {'name': cbd_name})
        cbd = [x for x in cbd if x.state == 'running']
        if cbd:
            return cbd[0]
        else:
            raise ValueError("Failed to create new Cloubreak Instance")
    else:
        raise ValueError("Cloudbreak AutoDeploy only supported on EC2")


def add_sec_rule_to_ec2_group(session, rule, sec_group_id):
    try:
        session.ex_authorize_security_group_ingress(
            sec_group_id,
            **rule
        )
    except BaseHTTPError as e:
        if 'Duplicate' in e.message:
            pass
        else:
            raise e


# noinspection PyCompatibility
def deploy_node(session, name, image, machine, deploy, params=None):
    obj = {
        'name': name,
        'image': image,
        'size': machine,
        'deploy': deploy,
        **params
    }
    return session.deploy_node(**obj)


# noinspection PyCompatibility
def create_node(session, name, image, machine, params=None):
    obj = {
        'name': name,
        'image': image,
        'size': machine,
        **params
    }
    return session.create_node(**obj)


def list_images(session, filters):
    return session.list_images(ex_filters=filters)


def list_sizes(session, cpu_min=2, cpu_max=16, mem_min=4096, mem_max=32768,
               disk_min=0, disk_max=0):
    sizes = session.list_sizes()
    machines = [
        x for x in sizes
        if mem_min <= x.ram <= mem_max
        and cpu_min <= x.extra['cpu'] <= cpu_max
        and disk_min <= x.disk <= disk_max
    ]
    return machines


def list_networks(session, filters=None):
    networks = session.ex_list_networks()
    if filters is None:
        return networks
    else:
        for key, val in filters.items():
            networks = [
                x for x in networks
                if val in utils.get_val(x, key)
            ]
        return networks


def list_subnets(session, filters=None):
    subnets = session.ex_list_subnets()
    if not filters:
        return subnets
    for key, val in filters.items():
        subnets = [
            x for x in subnets
            if val in utils.get_val(x, key)
        ]
    return subnets


def list_security_groups(session, filters=None):
    sec_groups = session.ex_get_security_groups()
    if not filters:
        return sec_groups
    for key, val in filters.items():
        sec_groups = [
            x for x in sec_groups
            if val in utils.get_val(x, key)
        ]
    return sec_groups


def list_keypairs(session, filters=None):
    key_pairs = session.list_key_pairs()
    if not filters:
        return key_pairs
    for key, val in filters.items():
        key_pairs = [
            x for x in key_pairs
            if val in utils.get_val(x, key)
        ]
    return key_pairs


def list_nodes(session, filters=None):
    log.info("Fetching Nodes matching Namespace in current session")
    nodes = session.list_nodes()
    if not filters:
        return nodes
    for key, val in filters.items():
        nodes = [
            x for x in nodes
            if val in utils.get_val(x, key)
        ]
    return nodes
