# -*- coding: utf-8 -*-

"""
For interactions with Deployment Infrastructure

Warnings:
    Experimental, not extensively tested
"""

from __future__ import absolute_import
import logging
import requests
from time import sleep
import socket
import Crypto
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.common.exceptions import BaseHTTPError
from libcloud.common.types import InvalidCredsError
from libcloud.common.google import ResourceNotFoundError
from libcloud.compute.base import NodeLocation
from libcloud.compute.base import NodeAuthSSHKey
from libcloud.compute.drivers.azure_arm import AzureNodeDriver
from libcloud.storage.types import ContainerDoesNotExistError
import boto3
from whoville import config, utils, security
from encodings.base64_codec import base64_encode
from test.test_os import resource
import base64

__all__ = ['create_libcloud_session', 'create_boto3_session', 'get_cloudbreak',
           'create_cloudbreak', 'add_sec_rule_to_ec2_group', 'deploy_node',
           'create_node', 'list_images', 'list_sizes', 'list_networks',
           'list_subnets', 'list_security_groups', 'list_keypairs',
           'list_nodes']

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

namespace = config.profile['namespace']
namespace = namespace if namespace else ''
preferred_cb_ver = '2.7.1'

def create_libcloud_session():
    provider = config.profile.get('platform')['provider']
    cls = get_driver(getattr(Provider, provider))
    params = config.profile.get('platform')
    if not params:
        raise ValueError("Profile not configured with Platform Parameters")
    
    if provider == 'EC2':
        return cls(
                **{x: y for x, y in params.items()
                if x in ['key', 'secret', 'region']}
            )
    elif provider == 'AZURE_ARM':
        return cls(tenant_id=params['tenant'],
                   subscription_id=params['subscription'], 
                   key=params['application'],
                   secret=params['secret'],
                   region=params['region']
            )
    elif provider == 'GCE':
        return cls(params['serviceaccount'], 
                   params['apikeypath'], 
                   project=params['project']
            )

def create_libcloud_storge_session():
    from libcloud.storage.types import Provider
    from libcloud.storage.providers import get_driver
    
    provider = config.profile.get('objectstore')
    if provider == 'wasb':
        cls = get_driver(Provider.AZURE_BLOBS)
        return cls(key=config.profile.get('bucket'), 
               secret=config.profile.get('bucketkey'))
    else:
        raise ValueError("Azure infra access keys not defined in Profile")
        
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

def create_azure_compute_session():
    from azure.common.credentials import ServicePrincipalCredentials
    from azure.mgmt.compute import ComputeManagementClient
    
    platform = config.profile.get('platform')
    if platform['provider'] == 'AZURE_ARM':
        subscription_id = platform['subscription']
        credentials = ServicePrincipalCredentials(
            client_id=platform['application'],
            secret=platform['secret'],
            tenant=platform['tenant']
        )
        return ComputeManagementClient(credentials, subscription_id)
    else:
        raise ValueError("Azure infra access keys not defined in Profile")

def create_azure_network_session():
    from azure.common.credentials import ServicePrincipalCredentials
    from azure.mgmt.network import NetworkManagementClient
    platform = config.profile.get('platform')
    if platform['provider'] == 'AZURE_ARM':
        subscription_id = platform['subscription']
        credentials = ServicePrincipalCredentials(
            client_id=platform['application'],
            secret=platform['secret'],
            tenant=platform['tenant']
        )
        return NetworkManagementClient(credentials, subscription_id)
    else:
        raise ValueError("Azure infra access keys not defined in Profile")

def create_azure_security_session():
    from azure.common.credentials import ServicePrincipalCredentials
    from azure.mgmt.network import NetworkResourceProviderClient
    platform = config.profile.get('platform')
    if platform['provider'] == 'AZURE_ARM':
        subscription_id = platform['subscription']
        credentials = ServicePrincipalCredentials(
            client_id=platform['application'],
            secret=platform['secret'],
            tenant=platform['tenant']
        )
        return NetworkResourceProviderClient(credentials, subscription_id)
    else:
        raise ValueError("Azure infra access keys not defined in Profile")

def create_azure_storage_session():
    from azure.common.credentials import ServicePrincipalCredentials
    from azure.mgmt.storage import StorageManagementClient
    
    platform = config.profile.get('platform')
    if platform['provider'] == 'AZURE_ARM':
        subscription_id = platform['subscription']
        credentials = ServicePrincipalCredentials(
            client_id=platform['application'],
            secret=platform['secret'],
            tenant=platform['tenant']
        )
        return StorageManagementClient(credentials, subscription_id)
    else:
        raise ValueError("Infra provider is Azure but objectstore is not set to WASB")

def create_azure_resource_session():
    from azure.common.credentials import ServicePrincipalCredentials
    from azure.mgmt.resource import ResourceManagementClient
    platform = config.profile.get('platform')
    if platform['provider'] == 'AZURE_ARM':
        subscription_id = platform['subscription']
        credentials = ServicePrincipalCredentials(
            client_id=platform['application'],
            secret=platform['secret'],
            tenant=platform['tenant']
        )
        return ResourceManagementClient(credentials, subscription_id)
    else:
        raise ValueError("Azure infra access keys not defined in Profile")

def get_cloudbreak(s_libc=None, create=True, purge=False, create_wait=0):
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
            if create_wait:
                log.warning("About to create a Cloudbreak Instance! waiting "
                            "[%s] seconds for abort", create_wait)
                sleep(create_wait)
            cbd = create_cloudbreak(s_libc, cbd_name)
            log.info("Waiting for Cloudbreak Deployment to Complete")
            #public_dns_name = str(socket.gethostbyaddr(cbd.public_ips[0])[0])
            utils.wait_to_complete(
                utils.is_endpoint_up,
                'https://' + cbd.public_ips[0],
                whoville_delay=30,
                whoville_max_wait=600
            )
            return cbd


def create_cloudbreak(session, cbd_name):
    public_ip = requests.get('http://ipv4.icanhazip.com').text.rstrip()
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
        s_boto3 = create_boto3_session()
        client_cf = s_boto3.client('cloudformation')
        cf_stacks = client_cf.list_stacks()
        log.info("Looking for existing Cloud Formation stacks within namespace "
                 "[%s]", namespace)
        for cf_stack in cf_stacks['StackSummaries']:
            if namespace in cf_stack['StackName']:
                log.info("Found Cloud Formation [%s], deleting to avoid collision "
                         "with Cloudbreak cluster creation...",
                         cf_stack['StackName'])
                client_cf.delete_stack(StackName=cf_stack['StackName'])
                
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
        subnets = sorted(subnets, key=lambda k: k.state)
        ec2_resource = s_boto3.resource('ec2')
        if not subnets:
            raise ValueError("Expecting at least one subnet on a network")
        subnet = [x for x in subnets
                  if ec2_resource.Subnet(x.id).map_public_ip_on_launch]
        if not subnet:
            raise ValueError("There are no subnets with auto provisioning of public IPs enabled..." 
                              "enable public IP auto provisioning on at least one subnet in the default VPC")
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
        # security group loopback doesn't work well on AWS, need to use subnet
        net_rules.append(
            {
                'protocol': -1,
                'cidr_ips': [subnet.extra['cidr_block']],
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
                       
        log.info("Creating Static IP for Cloudbreak")
        try:
            static_ips = [x for x in session.ex_describe_all_addresses()
                          if x.instance_id is None]
        except InvalidCredsError:
            static_ips = None
        if not static_ips:
            static_ip = session.ex_allocate_address()
        else:
            static_ip = static_ips[0]
        if not static_ip:
            raise ValueError("Couldn't get a Static IP for Cloudbreak") 
                       
        # This is just a tidy way of specifying a script
        cb_ver = config.profile.get('cloudbreak_ver')
        cb_ver = str(cb_ver) if cb_ver else preferred_cb_ver
        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "export cb_ver=" + cb_ver,
            "export uaa_secret=" + security.get_secret('masterkey'),
            "export uaa_default_pw=" + security.get_secret('password'),
            "export uaa_default_email=" + config.profile['email'],
            "export public_ip=" + static_ip.ip,
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
        session.ex_associate_address_with_node(cbd, static_ip)
        # Assign Role ARN
        infra_arn = config.profile['platform']['infraarn']
        client = s_boto3.client('ec2')
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
    if session.type == 'azure_arm':
        #ssh_key = NodeAuthSSHKey(config.profile['sshkey_pub'])
        ssh_key = config.profile['sshkey_pub']
        resource_group = namespace+'cloudbreak-group'
        storage_account_name = config.profile.get('bucket')
        network_name = namespace+'cloudbreak-network'
        subnet_name = namespace+'cloudbreak-subnet'
        sec_group_name = namespace+'cloudbreak-secgroup'
        public_ip_name = namespace+'cloudbreak-ip'
        nic_name = namespace+'cloudbreak-nic'
        disk_account_name = namespace+'diskaccount'
        disk_account_name = disk_account_name.replace('-', '')
        
        log.info("Creating Resource Group...")        
        azure_resource_client = create_azure_resource_session()
        azure_resource_client.resource_groups.create_or_update(resource_group, {'location': config.profile.get('platform')['region']})
                
        image = session.list_images(ex_publisher='OpenLogic',ex_offer='CentOS-CI',ex_sku='7-CI')
        if not image:
            raise ValueError("Couldn't find a valid Centos7 Image")
        else:
            image = image[-1]
        
        machines = list_sizes_azure(
            session, cpu_min=4, cpu_max=4, mem_min=16384, mem_max=20480
        )
        if not machines:
            raise ValueError("Couldn't find a VM of the right size")
        else:
            machine = machines[0]
        
        #networks = list_networks(session, {'name': network_name})
        #network = networks[-1]
        #subnet = session.ex_list_subnets(network)[0]
        
        log.info("Checking for disk storage account...")
        azure_storage_client = create_azure_storage_session()
        try:
            azure_storage_client.storage_accounts.create(
                resource_group,
                disk_account_name,
                {
                    'location': config.profile.get('platform')['region'],
                    'sku': {'name': 'standard_lrs'},
                    'kind': 'StorageV2'
                }
            ).wait()
        except Exception:
            log.info("Found existing os disk account...")
        
        log.info("Looking for existing network resources...")
        azure_network_client = create_azure_network_session()    
        try:
            log.info("Getting Vnet...")
            network = azure_network_client.virtual_networks.get(resource_group, network_name)
            log.info("Getting Network Interface...")
            nic = azure_network_client.network_interfaces.get(resource_group, nic_name)
            log.info("Getting Public IP...")
            public_ip = azure_network_client.public_ip_addresses.get(resource_group, public_ip_name)
        except Exception:
            log.info("No Vnet exists for this namepsace, creating...")
            network = azure_network_client.virtual_networks.create_or_update(
                resource_group,
                network_name,
                {
                    'location': config.profile.get('platform')['region'],
                    'address_space': {'address_prefixes': ['10.0.0.0/16']}
                }
            )
            network = network.result()
            
            log.info("Creating Subnet...")
            subnet = azure_network_client.subnets.create_or_update(
                resource_group,
                network_name,
                subnet_name,
                {'address_prefix': '10.0.0.0/24'}
            )
            
            log.info("Creating Public IP...")
            public_ip = azure_network_client.public_ip_addresses.create_or_update(
                resource_group,
                public_ip_name,
                {
                    'location': config.profile.get('platform')['region'],
                    'public_ip_allocation_method': 'static'
                }
            )
            
            subnet = subnet.result()
            public_ip = public_ip.result()
            
            log.info("Creating Security Group...")
            sec_group = azure_network_client.network_security_groups.create_or_update(
                resource_group,
                sec_group_name,
                {
                    'location': config.profile.get('platform')['region'],
                    'security_rules': [
                        {
                            'name': 'ssh_rule',
                            'description': 'Allow SSH',
                            'protocol': 'Tcp',
                            'source_port_range': '*',
                            'destination_port_range': '22',
                            'source_address_prefix': 'Internet',
                            'destination_address_prefix': '*',
                            'access': 'Allow',
                            'priority': 100,
                            'direction': 'Inbound'
                        },
                        {
                            'name': 'http_rule',
                            'description': 'Allow HTTP',
                            'protocol': 'Tcp',
                            'sourcePortRange': '*',
                            'destinationPortRange': '80',
                            'sourceAddressPrefix': 'Internet',
                            'destinationAddressPrefix': '*',
                            'access': 'Allow',
                            'priority': 101,
                            'direction': 'Inbound'
                        },
                        {
                            'name': 'https_rule',
                            'provisioningState': 'Succeeded',
                            'description': 'Allow HTTPS',
                            'protocol': 'Tcp',
                            'sourcePortRange': '*',
                            'destinationPortRange': '443',
                            'sourceAddressPrefix': 'Internet',
                            'destinationAddressPrefix': '*',
                            'access': 'Allow',
                            'priority': 102,
                            'direction': 'Inbound'
                        },
                        {
                            'name': 'cb_https_rule',
                            'provisioningState': 'Succeeded',
                            'description': 'Allow CB HTTPS',
                            'protocol': 'Tcp',
                            'sourcePortRange': '*',
                            'destinationPortRange': '9443',
                            'sourceAddressPrefix': 'Internet',
                            'destinationAddressPrefix': '*',
                            'access': 'Allow',
                            'priority': 103,
                            'direction': 'Inbound'
                        }
                    ]
                }
            )
            sec_group = sec_group.result()
            
            log.info("Creating Network Interface...")
            nic = azure_network_client.network_interfaces.create_or_update(
                resource_group,
                nic_name,
                {
                    'location': config.profile.get('platform')['region'],
                    'network_security_group': {'id': sec_group.id},
                    'ip_configurations': [{
                        'name': 'default',
                        'subnet': {'id': subnet.id},
                        'public_ip_address': {'id': public_ip.id}
                    }]
                }   
            )
            nic = nic.result()
        
        public_ip = public_ip.ip_address
        
        cb_ver = config.profile.get('cloudbreak_ver')
        cb_ver = str(cb_ver) if cb_ver else preferred_cb_ver
        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "yum install -y wget",
            "wget -O jq https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64",
            "chmod +x ./jq",
            "cp jq /usr/bin",
            "export cb_ver=" + cb_ver,
            "export uaa_secret=" + security.get_secret('masterkey'),
            "export uaa_default_pw=" + security.get_secret('password'),
            "export uaa_default_email=" + config.profile['email'],
            "export public_ip=" + public_ip,
            "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/bootstrap/v2/cbd_bootstrap_centos7.sh)"
        ]
        script = '\n'.join(script_lines)
        script = script.encode()
        script = str(base64.urlsafe_b64encode(script)).replace("b'","").replace("'","")

        log.info("Creating Virtual Machine...")
        log.info("with custom_data string: " + script)
        azure_compute_client = create_azure_compute_session()
        cbd = azure_compute_client.virtual_machines.create_or_update(
            resource_group,
            cbd_name,
            {
                'location': config.profile.get('platform')['region'],
                'os_profile': {
                    'computer_name': cbd_name,
                    'admin_username': 'centos',
                    'linux_configuration': {
                        'disable_password_authentication': True,
                        'ssh': {
                            'public_keys': [{
                                'path': '/home/{}/.ssh/authorized_keys'.format('centos'),
                                'key_data': ssh_key
                            }]
                        }
                    }, 
                    'custom_data': script
                },
                'hardware_profile': {
                    'vm_size': 'Standard_DS3_v2'
                },
                'storage_profile': {
                    'image_reference': {
                        'publisher': 'Redhat',
                        'offer': 'RHEL',
                        'sku': '7-RAW-CI',
                        'version': 'latest'
                    },
                    'os_disk': {
                        'name': cbd_name,
                        'create_option': 'fromImage',
                        'vhd': {'uri': 'https://{}.blob.core.windows.net/vhds/{}.vhd'.format(disk_account_name, cbd_name)}
                    },
                },
                'network_profile': {
                    'network_interfaces': [{'id': nic.id,'primary': True}]
                }
            }
        )
        
        log.info("Waiting for Cloudbreak Instance to be Available...")
        cbd.wait()

        cbd = list_nodes(session, {'name': cbd_name})
        cbd = [x for x in cbd if x.state == 'running']
        if cbd:
            return cbd[0]
        else:
            raise ValueError("Failed to create new Cloubreak Instance")
    elif session.type == 'gce': 
        project = config.profile['platform']['project']
        region = config.profile['platform']['region']
        cbd_name = namespace+'cloudbreak'
        public_ip_name = namespace+'cloudbreak-public-ip'
        subnet_name = namespace+'cloudbreak-subnet'
        firewall_name = namespace+'cloudbreak-secgroup'
        ssh_key = config.profile['sshkey_pub']
        
        log.info("Looking for existing network...")
        networks = session.ex_list_networks()
        network = [
            x for x in networks
            if x.mode == 'auto' 
            ]
        if not network:
            raise ValueError("There should be at least one network, this "
                 "is rather unexpected")
        else:
            network = network[-1]
            log.info("Found network: " + network.name)
        
        log.info("Looking for existing subnets...")
        subnets = session.ex_list_subnetworks(region=region)
        subnet = [
            x for x in subnets
            if x.name == 'default'
            ]
        if not subnet:
            session.ex_create_subnetwork(name=subnet_name,region=region,network=network)
        else:
            subnet = subnet[-1]
            subnet_name = subnet.name
            log.info("Found existing subnet called: " + subnet_name)
        
        log.info("Getting Public IP...")
        try:
            public_ip = session.ex_get_address(name=public_ip_name,region=region)
            log.info("Found existing Public IP matching name: " + public_ip_name)
        except ResourceNotFoundError:
            public_ip = session.ex_create_address(name=public_ip_name, region=region)
            log.info("Creating new Public IP with name: " + public_ip_name)
            
        images = session.list_images()
        image = [
            x for x in images 
            if x.extra['family'] == 'centos-7' 
            and 'centos-7' in x.name 
            ]
        
        zones = session.ex_list_zones()
        zone = [
            x for x in zones
            if region in x.name
            and x.status == 'UP'
            ]
        if not zone:
            raise ValueError("Couldn't find a zone for the requested region...")
        else:
            zone = zone[-1]
        
        if not image:
            raise ValueError("Couldn't find a valid Centos7 Image")
        else:
            image = image[-1]
        
        machines = list_sizes_gce(
            session, location=region, cpu_min=4, cpu_max=4, mem_min=13000, mem_max=20000
        )
        if not machines:
            raise ValueError("Couldn't find a VM of the right size")
        else:
            machine = machines[-1]
        
        log.info("Creating Security Group...")
        try:
            firewall = session.ex_get_firewall(name=firewall_name)
            log.info("Found existing firewall definition called: " + firewall_name)
        except ResourceNotFoundError:
            log.info("Creating new firewall definition called: " + firewall_name)
            net_rules = [
                            {'IPProtocol': 'tcp',
                             'ports': ['22','443','9443']
                            }
                        ]
            firewall = session.ex_create_firewall(name=firewall_name,                                        
                                               network=network,  
                                               allowed=net_rules,
                                               target_tags=[cbd_name]
                                            )
        
        cb_ver = config.profile.get('cloudbreak_ver')
        cb_ver = str(cb_ver) if cb_ver else preferred_cb_ver
        script_lines = [
                    "#!/bin/bash",
                    "cd /root",
                    "export cb_ver=" + cb_ver,
                    "export uaa_secret=" + security.get_secret('masterkey'),
                    "export uaa_default_pw=" + security.get_secret('password'),
                    "export uaa_default_email=" + config.profile['email'],
                    "export public_ip=" + public_ip.address,
                    "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
                    "/whoville/master/bootstrap/v2/cbd_bootstrap_centos7.sh)"
                ]
        script = '\n'.join(script_lines)
        
        metadata =  {
                        'items': [
                            {
                                'key': 'startup-script',
                                'value': script
                            },
                            {
                                'key': 'ssh-keys',
                                'value': 'centos:' + ssh_key
                            }
                        ]
                    }   
        
        log.info("Creating Cloudbreak instance...")
        cbd = session.create_node(name=cbd_name, 
                    size=machine, 
                    image=image, 
                    location=zone, 
                    ex_network=network,
                    external_ip=public_ip, 
                    ex_metadata=metadata,
                    ex_tags=[cbd_name]
                )
        
        log.info("Waiting for Cloudbreak Instance to be Available...")
        session.wait_until_running(nodes=[cbd])
        cbd = list_nodes(session, {'name': cbd_name})
        cbd = [x for x in cbd if x.state == 'running']
        if cbd:
            return cbd[0]
        else:
            raise ValueError("Failed to create new Cloubreak Instance")
    else:
        raise ValueError("Cloudbreak AutoDeploy only supported on EC2, Azure, and GCE")
 

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

def add_sec_rule_azure(session, resource_group, sec_group_name, security_rule_name, security_rule_parameters):
    sec_rule = session.security_rules.create_or_update(
                resource_group,
                sec_group_name,
                security_rule_name,
                security_rule_parameters
            )
    return sec_rule.result()

def add_sec_rule_gce(session, sec_group_name, security_rule):
    firewall = session.ex_get_firewall(name=sec_group_name)
    firewall.allowed.append(security_rule)
    session.ex_update_firewall(firewall)
    
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


def list_sizes_azure(session, cpu_min=2, cpu_max=16, mem_min=4096, mem_max=32768,
               disk_min=0, disk_max=10475520):
    sizes = session.list_sizes()
    machines = [
        x for x in sizes
        if mem_min <= x.ram <= mem_max
        and cpu_min <= x.extra['numberOfCores'] <= cpu_max
        and disk_min <= x.disk <= disk_max
    ]
    return machines

def list_sizes_gce(session, location=None, cpu_min=2, cpu_max=16, mem_min=4096, mem_max=32768,
               disk_min=0, disk_max=10475520):
    sizes = session.list_sizes(location=location)
    machines = [
        x for x in sizes
        if mem_min <= x.ram <= mem_max
        and cpu_min <= x.extra['guestCpus'] <= cpu_max
        and location in x.extra['zone'].extra['description'] 
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


def list_all_aws_nodes():
    log.info("Fetching descriptions of all nodes in all AWS Regions."
             " This will be slow...")
    b3 = create_boto3_session()
    ec2 = b3.client('ec2')
    regions = [x['RegionName'] for x in ec2.describe_regions()['Regions']]
    nodes = []
    for r in regions:
        ec2 = b3.client('ec2', r)
        reservations = ec2.describe_instances()['Reservations']
        log.info("Found [%d] Nodes in Region [%s]",
                 len(reservations), r)
        if reservations:
            nodes += reservations
    log.info("All known regions checked, returning list")
    return nodes


def get_aws_node_summary(node_list=None):
    # ToDo: https://wiki.hortonworks.com/pages/viewpage.action?spaceKey=SE&title=Manual+Cloud+Cleanup+Procedure
    summary = []
    node_list = node_list if node_list else list_all_aws_nodes()
    [[summary.append(
        {p: q for p, q in y.items() if p in ['Placement', 'State', 'Tags']})
      for y in x['Instances']] for x in node_list]
    return summary

