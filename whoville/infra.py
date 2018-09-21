# -*- coding: utf-8 -*-

"""
For interactions with Deployment Infrastructure

Warnings:
    Experimental, not extensively tested
"""

from __future__ import absolute_import
import logging
import requests
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.common.exceptions import BaseHTTPError
import boto3
import whoville


__all__ = ['create_libcloud_session', 'create_boto3_session', 'get_cloudbreak',
           'create_cloudbreak', 'add_sec_rule_to_ec2_group', 'deploy_node',
           'create_node', 'list_images', 'list_sizes', 'list_networks',
           'list_subnets', 'list_security_groups', 'list_keypairs',
           'list_nodes']

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

namespace = whoville.config.profile['deploy']['namespace']
namespace = namespace if namespace else ''


def create_libcloud_session(provider='EC2'):
    cls = get_driver(getattr(Provider, provider))
    return cls(
        **{x:y for x,y in whoville.config.profile['infra'][provider].items()
            if x in ['key', 'secret', 'region']}
    )


def create_boto3_session():
    if 'EC2' in whoville.config.profile['infra']:
        params = whoville.config.profile['infra']['EC2']
        return boto3.Session(
            aws_access_key_id=params['key'],
            aws_secret_access_key=params['secret'],
            region_name=params['region']
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
            log.info("CLoudbreak [%s] found, returning instance",
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
            whoville.utils.wait_to_complete(
                whoville.utils.is_endpoint_up,
                'https://' + cbd.extra['dns_name'],
                whoville_delay=30,
                whoville_max_wait=600
            )
            return cbd


def create_cloudbreak(session, cbd_name):
    # TODO: Implement separate namespaces for infra and deploy
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
        }
    ]
    if session.type == 'ec2':
        image = list_images(
            session,
            filters={
                'name': '*CentOS Linux 7*x86_64* 18*',
            }
        )[-1]
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
        machine = list_sizes(session, cpu_min=4, cpu_max=4, mem_min=16000,
                             mem_max=20000)[-1]
        network = list_networks(session, {'name': 'default'})[-1]
        subnet = list_subnets(session, {'extra.vpc_id': network.id})[-1]
        sec_group = list_security_groups(session, {'name': namespace})
        if not sec_group:
            sec_group = session.ex_create_security_group(
                name=namespace + 'whoville-default',
                description=namespace + 'whoville-default Security Group',
                vpc_id=network.id
            )
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
        ssh_key = list_keypairs(session, {'name': 'field'})
        if not ssh_key:
            ssh_key = session.import_key_pair_from_string(
                name='field',
                key_material=whoville.config.profile['deploy']['sshkey_pub']
            )
        else:
            ssh_key = ssh_key[0]

        script = '''#!/bin/bash
        curl -s https://raw.githubusercontent.com/Chaffelson/whoville/hdp3cbd/bootstrap/v2/cbd_bootstrap_centos7.sh | bash'''
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
        # TODO: Reuse Elastic IPs isntead of making new each time
        elastic_ip = session.ex_allocate_address()
        session.ex_associate_address_with_node(cbd, elastic_ip)
        # Assign Role ARN
        s_boto3 = create_boto3_session()
        client = s_boto3.client('ec2')
        client.associate_iam_instance_profile(
            IamInstanceProfile={
                'Arn': whoville.config.profile['infra']['EC2']['infraarn'],
                'Name': whoville.config.profile['infra']['EC2']['infraarn'].rsplit('/')[-1]
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


def deploy_node(session, name, image, machine, deploy, params=None):
    obj = {
        'name': name,
        'image': image,
        'size': machine,
        'deploy': deploy,
        **params
    }
    return session.deploy_node(**obj)


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
    if not filter:
        return networks
    for key, val in filters.items():
        networks = [
            x for x in networks
            if val in whoville.utils.get_val(x, key)
        ]
    return networks


def list_subnets(session, filters=None):
    subnets = session.ex_list_subnets()
    if not filters:
        return subnets
    for key, val in filters.items():
        subnets = [
            x for x in subnets
            if val in whoville.utils.get_val(x, key)
        ]
    return subnets


def list_security_groups(session, filters=None):
    sec_groups = session.ex_get_security_groups()
    if not filters:
        return sec_groups
    for key, val in filters.items():
        sec_groups = [
            x for x in sec_groups
            if val in whoville.utils.get_val(x, key)
        ]
    return sec_groups


def list_keypairs(session, filters=None):
    key_pairs = session.list_key_pairs()
    if not filters:
        return key_pairs
    for key, val in filters.items():
        key_pairs = [
            x for x in key_pairs
            if val in whoville.utils.get_val(x, key)
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
            if val in whoville.utils.get_val(x, key)
        ]
    return nodes
