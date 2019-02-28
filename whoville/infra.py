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
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.common.exceptions import BaseHTTPError
from libcloud.common.types import InvalidCredsError
from libcloud.common.google import ResourceNotFoundError
from botocore.exceptions import ClientError
from azure.common.credentials import ServicePrincipalCredentials
import adal
import boto3
from whoville import config, utils, security
import base64
import pexpect
from pexpect import pxssh 
from pexpect.exceptions import EOF
from pexpect.pxssh import ExceptionPxssh

__all__ = ['create_libcloud_session', 'create_boto3_session', 'get_cloudbreak',
           'create_cloudbreak', 'add_sec_rule_to_ec2_group', 'deploy_node',
           'create_node', 'list_images', 'list_sizes_aws', 'list_networks',
           'list_subnets', 'list_security_groups', 'list_keypairs', 'list_nodes']

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# ADAL for Azure is verbose, reducing output
adal.log.set_logging_options({'level': 'WARNING'})

_horton = utils.Horton()


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
                   secret=config.profile.get('bucketkey')
                   )
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


def get_azure_token():
    platform = config.profile.get('platform')
    if platform['provider'] == 'AZURE_ARM':
        credentials = ServicePrincipalCredentials(
            client_id=platform['application'],
            secret=platform['secret'],
            tenant=platform['tenant']
        )
    else:
        raise ValueError("Azure infra access keys not defined in Profile")
    return credentials


def create_azure_session(token, service):
    assert service in ['compute', 'network', 'security', 'storage', 'resource']
    assert isinstance(token, ServicePrincipalCredentials)
    platform = config.profile.get('platform')
    if 'subscription' in platform and platform['subscription']:
        sub_id = platform['subscription']
    else:
        raise ValueError("Subscription ID not in Azure Platform Definition")
    if service == 'compute':
        from azure.mgmt.compute import ComputeManagementClient
        return ComputeManagementClient(token, sub_id)
    if service == 'network':
        from azure.mgmt.network import NetworkManagementClient
        return NetworkManagementClient(token, sub_id)
    if service == 'security':
        from azure.mgmt.network import NetworkResourceProviderClient
        return NetworkResourceProviderClient(token, sub_id)
    if service == 'storage':
        from azure.mgmt.storage import StorageManagementClient
        return StorageManagementClient(token, sub_id)
    if service == 'resource':
        from azure.mgmt.resource import ResourceManagementClient
        return ResourceManagementClient(token, sub_id)


def get_cloudbreak(s_libc=None, create=True, purge=False, create_wait=0):
    if not s_libc:
        s_libc = create_libcloud_session()

    cbd_name = _horton.namespace + 'cloudbreak'
    cbd_nodes = list_nodes(s_libc, {'name': cbd_name})
    cbd = [x for x in cbd_nodes if x.state == 'running']
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
            utils.wait_to_complete(
                utils.is_endpoint_up,
                'https://' + cbd.public_ips[0],
                whoville_delay=30,
                whoville_max_wait=600
            )
            return cbd

def get_k8s(s_libc=None, create=True, purge=False, create_wait=0):
    if not s_libc:
        s_libc = create_libcloud_session()
        
    user_name = config.profile['k8s_user']
    ssh_key_path = config.profile['k8s_ssh_key_path']
    cbd_name = namespace + 'k8s-master'
    k8s_nodes = []
    
    num_minions = config.profile['k8s_minion_count']
    minion_names = []
    minion_filter = {}
    for x in range(num_minions):
        minion_names.append(namespace+'k8s-minion-'+str(x))
    
    cbd_nodes = list_nodes(s_libc, {'name': cbd_name})
    cbd = [x for x in cbd_nodes if x.state == 'running']
    if cbd:
        if not purge:
            log.info("K8S Master [%s] found, returning instance",
                     cbd[0].name)
            return cbd[0]
        else:
            log.info("K8S Master found, Purge is True, destroying Master and Minions...")
            log.info("Destroying Master...")
            [s_libc.destroy_node(x) for x in cbd]
            log.info("Destroying Minions...")
            for minion in minion_names:
                minion_filter['name'] = minion
                minion_nodes = list_nodes(s_libc, minion_filter)
                minion_nodes = [x for x in minion_nodes if x.state == 'running']
                [s_libc.destroy_node(x) for x in minion_nodes]
            cbd = None
    if not cbd:
        log.info("K8S Master, [%s] not found", cbd_name)
        if not create:
            log.info("K8S Master not found, Create is False, returning None")
            return None
        else:
            log.info("K8S Master is None, Create is True - deploying new "
                     "K8S Cluster [%s]", cbd_name)
            if create_wait:
                log.warning("About to create a K8S Cluster! waiting "
                            "[%s] seconds for abort", create_wait)
                sleep(create_wait)
            cbd = create_k8s(s_libc, cbd_name)
            k8s_nodes.append(cbd)
            log.info("Waiting for K8S Master [%s] to be created", cbd_name)
            utils.wait_to_complete(
                utils.is_remote_file_present,
                cbd.public_ips[0],
                user_name,
                ssh_key_path,
                whoville_delay=30,
                whoville_max_wait=600
            )
            
            cluster_join_string = initialize_k8s_master(cbd.public_ips[0], user_name, ssh_key_path)
            
            for x in minion_names:
                cbd = create_k8s(s_libc, x)
                log.info("Waiting for K8S Minion [%s] to be created", x)
                utils.wait_to_complete(
                    utils.is_remote_file_present,
                    cbd.public_ips[0],
                    user_name,
                    ssh_key_path,
                    whoville_delay=30,
                    whoville_max_wait=600
                )
                
                initialize_k8s_minion(cbd.public_ips[0], user_name, ssh_key_path, cluster_join_string)
                k8s_nodes.append(cbd)
            
            return k8s_nodes


def aws_clean_cloudformation(s_boto3):
    client_cf = s_boto3.client('cloudformation')
    cf_stacks = client_cf.list_stacks()
    log.info("Looking for existing Cloud Formation stacks within namespace"
             " [%s]", _horton.namespace)
    for cf_stack in cf_stacks['StackSummaries']:
        if _horton.namespace in cf_stack['StackName']:
            log.info("Found Cloud Formation [%s], deleting to avoid "
                     "collision with Cloudbreak cluster creation...",
                     cf_stack['StackName'])
            client_cf.delete_stack(StackName=cf_stack['StackName'])


def create_cloudbreak(session, cbd_name):
    public_ip = requests.get('https://ipv4.icanhazip.com').text.rstrip()
    net_rules = [
        {
            'protocol': 'tcp',  # required for Cloudbreak
            'from_port': 9443,
            'to_port': 9443,
            'cidr_ips': ['0.0.0.0/0'],
            'description': 'Cloudbreak'
        },
        {
            'protocol': -1,  # initiators public IP
            'from_port': 1,
            'to_port': 65535,
            'cidr_ips': [public_ip + '/32'],
            'description': 'DeployerConnect'
        },
        {
            'protocol': 'tcp',  # general secured access
            'from_port': 443,
            'to_port': 443,
            'cidr_ips': ['0.0.0.0/0'],
            'description': 'SSL'
        },
        {
            'protocol': 'tcp',  # general secured access
            'from_port': 8443,
            'to_port': 8443,
            'cidr_ips': ['0.0.0.0/0'],
            'description': 'Dataplane PublicIP'
        }
    ]
    if 'cidr_whitelist' in config.profile:
        for whitelist_cidr in config.profile['cidr_whitelist']:
            net_rules.append(
                {
                    'protocol': -1,
                    'cidr_ips': [whitelist_cidr],
                    'from_port': 0,
                    'to_port': 0,
                    'description': 'fromProfileWhitelist'
                }
            )
    if session.type == 'ec2':
        s_boto3 = create_boto3_session()
        aws_clean_cloudformation(s_boto3)
        log.info("Selecting OS Image for Cloudbreak")
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
        log.info("Fetching list of suitable machine types")
        machines = list_sizes_aws(
            session, cpu_min=4, cpu_max=4, mem_min=16000, mem_max=20000
        )
        if not machines:
            raise ValueError("Couldn't find a VM of the right size")
        else:
            # Filtering to remove fancier machines
            filtered_machines = [
                x for x in machines
                if "m4." in x.id or "m5." in x.id
            ]
            machine = filtered_machines[-1]
        log.info("Fetching list of available networks")
        vpc, subnet = get_aws_network(session)
        log.info("Fetching Security groups matching namespace")
        sec_group = list_security_groups(session, {'name': _horton.namespace})
        if not sec_group:
            log.info("Namespace Security group not found, creating")
            _ = session.ex_create_security_group(
                name=_horton.namespace + 'whoville',
                description=_horton.namespace + 'whoville Security Group',
                vpc_id=vpc.id
            )
            sec_group = list_security_groups(session, {'name': _horton.namespace})[-1]
        else:
            sec_group = sec_group[-1]
        net_rules.append(
            {
                'protocol': -1,
                'group_pairs': [{'group_id': sec_group.id}],
                'from_port': 0,
                'to_port': 0,
                'description': 'Loopback SG'
            }
        )
        # security group loopback doesn't work well on AWS, need to use subnet
        net_rules.append(
            {
                'protocol': -1,
                'cidr_ips': [subnet.extra['cidr_block']],
                'from_port': 0,
                'to_port': 0,
                'description': 'loopback IP'
            }
        )
        for rule in net_rules:
            add_sec_rule_to_ec2_group(session, rule, sec_group.id)
        log.info("Checking for expected SSH Keypair")
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
        cb_ver = str(cb_ver) if cb_ver else config.cb_ver
        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "export cb_ver=" + cb_ver,
            "export uaa_secret=" + security.get_secret('MASTERKEY'),
            "export uaa_default_pw=" + security.get_secret('ADMINPASSWORD'),
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
        # Set Instance Tags
        sleep(5)
        log.info("Setting Instance Tags")
        session.ex_create_tags(
            resource=cbd,
            tags=config.profile['tags']
        )
        # inserting hard wait to bypass race condition where returned node ID
        # is not actually available to the list API call yet
        sleep(5)
        log.info("Waiting for Cloudbreak Instance to be Available...")
        session.wait_until_running(nodes=[cbd])
        log.info("Cloudbreak Infra Booted at [%s]", cbd)
        log.info("Assigning Static IP to Cloudbreak")
        try:
            session.ex_associate_address_with_node(
                cbd,
                static_ip
            )
        except BaseHTTPError as e:
            if 'InvalidParameterCombination' in e.message:
                session.ex_associate_address_with_node(
                    cbd,
                    static_ip,
                    domain='vpc' # needed for legacy AWS accounts
                )
            else:
                raise e
        # Assign Role ARN
        if 'infraarn' in config.profile['platform']:
            log.info("Found infraarn in Profile, associating with Cloudbreak")
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
        ssh_key = config.profile['sshkey_pub']
        resource_group = _horton.namespace + 'cloudbreak-group'
        network_name = _horton.namespace + 'cloudbreak-network'
        subnet_name = _horton.namespace + 'cloudbreak-subnet'
        sec_group_name = _horton.namespace + 'cloudbreak-secgroup'
        public_ip_name = _horton.namespace + 'cloudbreak-ip'
        nic_name = _horton.namespace + 'cloudbreak-nic'
        disk_account_name = _horton.namespace + 'diskaccount'
        disk_account_name = disk_account_name.replace('-', '')
        # ToDo: examine cleaning Azure Resource Groups
        log.info("Creating Resource Group...")
        token = get_azure_token()
        azure_resource_client = create_azure_session(token, 'resource')
        azure_resource_client.resource_groups.create_or_update(
            resource_group,
            {'location': config.profile.get('platform')['region']}
        )

        image = session.list_images(
            ex_publisher='OpenLogic',ex_offer='CentOS-CI',ex_sku='7-CI'
        )
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

        log.info("Checking for disk storage account, please wait...")
        azure_storage_client = create_azure_session(token, 'storage')
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
        azure_network_client = create_azure_session(token, 'network')
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
                            'name': 'knox_https_rule',
                            'provisioningState': 'Succeeded',
                            'description': 'Allow CB HTTPS',
                            'protocol': 'Tcp',
                            'sourcePortRange': '*',
                            'destinationPortRange': '8443',
                            'sourceAddressPrefix': 'Internet',
                            'destinationAddressPrefix': '*',
                            'access': 'Allow',
                            'priority': 103,
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
                            'priority': 104,
                            'direction': 'Inbound'
                        },
                        {
                            'name': 'altus_http_rule',
                            'provisioningState': 'Succeeded',
                            'description': 'Allow Altus HTTP',
                            'protocol': 'Tcp',
                            'sourcePortRange': '*',
                            'destinationPortRange': '7189',
                            'sourceAddressPrefix': 'Internet',
                            'destinationAddressPrefix': '*',
                            'access': 'Allow',
                            'priority': 105,
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
        # End network exception handling for missing vnet
        public_ip = public_ip.ip_address
        cb_ver = config.profile.get('cloudbreak_ver')
        cb_ver = str(cb_ver) if cb_ver else preferred_cb_ver
        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "yum install -y wget",
            "wget -O jq https://github.com/stedolan/jq/releases/download/"
            "jq-1.5/jq-linux64",
            "chmod +x ./jq",
            "cp jq /usr/bin",
            "export cb_ver=" + cb_ver,
            "export uaa_secret=" + security.get_secret('MASTERKEY'),
            "export uaa_default_pw=" + security.get_secret('ADMINPASSWORD'),
            "export uaa_default_email=" + config.profile['email'],
            "export public_ip=" + public_ip,
            "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
            "/whoville/master/bootstrap/v2/cbd_bootstrap_centos7.sh)"
        ]
        script = '\n'.join(script_lines)
        script = script.encode()
        script = str(base64.urlsafe_b64encode(script))\
            .replace("b'","").replace("'","")

        log.info("Creating Virtual Machine...")
        log.info("with custom_data string like: " + script[:100])
        azure_compute_client = create_azure_session(token, 'compute')
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
                                'path': '/home/{}/.ssh/authorized_keys'
                                .format('centos'),
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
                        'vhd': {
                            'uri': 'https://{}.blob.core.windows.net/'
                                   'vhds/{}.vhd'
                            .format(disk_account_name, cbd_name)}
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
        region = config.profile['platform']['region']
        cbd_name = _horton.namespace+'cloudbreak'
        public_ip_name = _horton.namespace+'cloudbreak-public-ip'
        subnet_name = _horton.namespace+'cloudbreak-subnet'
        firewall_name = _horton.namespace+'cloudbreak-firewall'
        ssh_key = config.profile['sshkey_pub']

        log.info("Looking for existing network...")
        networks = session.ex_list_networks()
        network = [
            x for x in networks
            if x.mode == 'auto'
            ]
        if not network:
            raise ValueError("There should be at least one network")
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
            session.ex_create_subnetwork(
                name=subnet_name,region=region,network=network
            )
        else:
            subnet = subnet[-1]
            subnet_name = subnet.name
            log.info("Found existing subnet called: " + subnet_name)

        log.info("Getting Public IP...")
        try:
            public_ip = session.ex_get_address(
                name=public_ip_name,region=region
            )
            log.info("Found existing Public IP matching name: "
                     + public_ip_name)
        except ResourceNotFoundError:
            public_ip = session.ex_create_address(
                name=public_ip_name, region=region
            )
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
            raise ValueError("Couldn't find a zone for the requested region..")
        else:
            zone = zone[-1]

        if not image:
            raise ValueError("Couldn't find a valid Centos7 Image")
        else:
            image = image[-1]

        machines = list_sizes_gce(
            session, location=zone, cpu_min=4, cpu_max=4, mem_min=13000,
            mem_max=20000
        )
        if not machines:
            raise ValueError("Couldn't find a VM of the right size")
        else:
            machine = machines[-1]

        log.info("Creating Firewall...")
        try:
            _ = session.ex_get_firewall(name=firewall_name)
            log.info("Found existing firewall definition called: " + firewall_name)
        except ResourceNotFoundError:
            log.info("Creating new firewall definition called: " + firewall_name)
            net_rules = [
                            {'IPProtocol': 'tcp',
                             'ports': ['22','443','8443','9443','7189']
                            }
                        ]
            _ = session.ex_create_firewall(name=firewall_name,
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
                    "export uaa_secret=" + security.get_secret('MASTERKEY'),
                    "export uaa_default_pw=" + security.get_secret('ADMINPASSWORD'),
                    "export uaa_default_email=" + config.profile['email'],
                    "export public_ip=" + public_ip.address,
                    "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
                    "/whoville/master/bootstrap/v2/cbd_bootstrap_centos7.sh)"
                ]
        script = '\n'.join(script_lines)
        metadata = {
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
        raise ValueError("Cloudbreak AutoDeploy only supported on EC2, Azure, "
                         "and GCE")

def create_k8s(session, cbd_name):
    public_ip = requests.get('https://ipv4.icanhazip.com').text.rstrip()
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
        log.info("Selecting OS Image for K8S Node")
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
        log.info("Fetching list of suitable machine types")
        machines = list_sizes_aws(
            session, cpu_min=4, cpu_max=4, mem_min=16000, mem_max=20000
        )
        if not machines:
            raise ValueError("Couldn't find a VM of the right size")
        else:
            machine = machines[-1]
        log.info("Fetching list of available networks")
        networks = list_networks(session)
        network = sorted(networks, key=lambda k: k.extra['is_default'])
        if not network:
            raise ValueError("There should be at least one network, this "
                             "is rather unexpected")
        else:
            network = network[-1]
        log.info("Fetching subnets in Network")
        subnets = list_subnets(session, {'extra.vpc_id': network.id})
        subnets = sorted(subnets, key=lambda k: k.state)
        ec2_resource = s_boto3.resource('ec2')
        if not subnets:
            raise ValueError("Expecting at least one subnet on a network")
        subnet = [x for x in subnets
                  if ec2_resource.Subnet(x.id).map_public_ip_on_launch]
        if not subnet:
            raise ValueError("There are no subnets with auto provisioning of "
                             "public IPs enabled..."
                             "enable public IP auto provisioning on at least "
                             "one subnet in the default VPC")
        else:
            subnet = subnet[0]
        log.info("Fetching Security groups matching namespace")
        sec_group = list_security_groups(session, {'name': namespace})
        if not sec_group:
            log.info("Namespace Security group not found, creating")
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
        log.info("Checking for expected SSH Keypair")
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
        log.info("Creating Static IP for K8S Node")
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
            raise ValueError("Couldn't get a Static IP for K8S Node") 

        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
            "/whoville/master/bootstrap/v2/k8s_bootstrap_centos7.sh)"
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
        # inserting hard wait to bypass race condition where returned node ID
        # is not actually available to the list API call yet
        sleep(5)
        log.info("Waiting for K8S Node to be Available...")
        session.wait_until_running(nodes=[cbd])
        log.info("K8S Node Booted at [%s]", cbd)
        log.info("Assigning Static IP to K8S Node")
        session.ex_associate_address_with_node(cbd, static_ip)
        # Assign Role ARN
        if 'infraarn' in config.profile['platform']:
            log.info("Found infraarn in Profile, associating with K8S Node")
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
            raise ValueError("Failed to create new K8S Node")
        
    if session.type == 'azure_arm':
        ssh_key = config.profile['sshkey_pub']
        resource_group = namespace + 'cloudbreak-group'
        network_name = namespace + 'cloudbreak-network'
        subnet_name = namespace + 'cloudbreak-subnet'
        sec_group_name = namespace + 'cloudbreak-secgroup'
        public_ip_name = namespace + 'cloudbreak-ip'
        nic_name = namespace + 'cloudbreak-nic'
        disk_account_name = namespace + 'diskaccount'
        disk_account_name = disk_account_name.replace('-', '')
        # ToDo: examine cleaning Azure Resource Groups
        log.info("Creating Resource Group...")
        token = get_azure_token()
        azure_resource_client = create_azure_session(token, 'resource')
        azure_resource_client.resource_groups.create_or_update(
            resource_group,
            {'location': config.profile.get('platform')['region']}
        )

        image = session.list_images(
            ex_publisher='OpenLogic',ex_offer='CentOS-CI',ex_sku='7-CI'
        )
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

        log.info("Checking for disk storage account, please wait...")
        azure_storage_client = create_azure_session(token, 'storage')
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
        azure_network_client = create_azure_session(token, 'network')
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
                            'name': 'knox_https_rule',
                            'provisioningState': 'Succeeded',
                            'description': 'Allow CB HTTPS',
                            'protocol': 'Tcp',
                            'sourcePortRange': '*',
                            'destinationPortRange': '8443',
                            'sourceAddressPrefix': 'Internet',
                            'destinationAddressPrefix': '*',
                            'access': 'Allow',
                            'priority': 103,
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
                            'priority': 104,
                            'direction': 'Inbound'
                        },
                        {
                            'name': 'altus_http_rule',
                            'provisioningState': 'Succeeded',
                            'description': 'Allow Altus HTTP',
                            'protocol': 'Tcp',
                            'sourcePortRange': '*',
                            'destinationPortRange': '7189',
                            'sourceAddressPrefix': 'Internet',
                            'destinationAddressPrefix': '*',
                            'access': 'Allow',
                            'priority': 105,
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
        # End network exception handling for missing vnet
        public_ip = public_ip.ip_address
        cb_ver = config.profile.get('cloudbreak_ver')
        cb_ver = str(cb_ver) if cb_ver else preferred_cb_ver
        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "yum install -y wget",
            "wget -O jq https://github.com/stedolan/jq/releases/download/"
            "jq-1.5/jq-linux64",
            "chmod +x ./jq",
            "cp jq /usr/bin",
            "export cb_ver=" + cb_ver,
            "export uaa_secret=" + security.get_secret('MASTERKEY'),
            "export uaa_default_pw=" + security.get_secret('ADMINPASSWORD'),
            "export uaa_default_email=" + config.profile['email'],
            "export public_ip=" + public_ip,
            "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
            "/whoville/master/bootstrap/v2/cbd_bootstrap_centos7.sh)"
        ]
        script = '\n'.join(script_lines)
        script = script.encode()
        script = str(base64.urlsafe_b64encode(script))\
            .replace("b'","").replace("'","")

        log.info("Creating Virtual Machine...")
        log.info("with custom_data string like: " + script[:100])
        azure_compute_client = create_azure_session(token, 'compute')
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
                                'path': '/home/{}/.ssh/authorized_keys'
                                .format('centos'),
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
                        'vhd': {
                            'uri': 'https://{}.blob.core.windows.net/'
                                   'vhds/{}.vhd'
                            .format(disk_account_name, cbd_name)}
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
            raise ValueError("There should be at least one network")
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
            session.ex_create_subnetwork(
                name=subnet_name,region=region,network=network
            )
        else:
            subnet = subnet[-1]
            subnet_name = subnet.name
            log.info("Found existing subnet called: " + subnet_name)

        log.info("Getting Public IP...")
        try:
            public_ip = session.ex_get_address(
                name=public_ip_name,region=region
            )
            log.info("Found existing Public IP matching name: "
                     + public_ip_name)
        except ResourceNotFoundError:
            public_ip = session.ex_create_address(
                name=public_ip_name, region=region
            )
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
            raise ValueError("Couldn't find a zone for the requested region..")
        else:
            zone = zone[-1]

        if not image:
            raise ValueError("Couldn't find a valid Centos7 Image")
        else:
            image = image[-1]

        machines = list_sizes_gce(
            session, location=region, cpu_min=4, cpu_max=4, mem_min=13000,
            mem_max=20000
        )
        if not machines:
            raise ValueError("Couldn't find a VM of the right size")
        else:
            machine = machines[-1]

        log.info("Creating Security Group...")
        try:
            _ = session.ex_get_firewall(name=firewall_name)
            log.info("Found existing firewall definition called: " + firewall_name)
        except ResourceNotFoundError:
            log.info("Creating new firewall definition called: " + firewall_name)
            net_rules = [
                            {'IPProtocol': 'tcp',
                             'ports': ['22','443','8443','9443','7189']
                            }
                        ]
            _ = session.ex_create_firewall(name=firewall_name,
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
                    "export uaa_secret=" + security.get_secret('MASTERKEY'),
                    "export uaa_default_pw=" + security.get_secret('ADMINPASSWORD'),
                    "export uaa_default_email=" + config.profile['email'],
                    "export public_ip=" + public_ip.address,
                    "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
                    "/whoville/master/bootstrap/v2/cbd_bootstrap_centos7.sh)"
                ]
        script = '\n'.join(script_lines)
        metadata = {
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
        raise ValueError("Cloudbreak AutoDeploy only supported on EC2, Azure, "
                         "and GCE")

def initialize_k8s_minion(target_host, user_name, ssh_key_path, join_string):
    log.info("Joining K8S Minion [%s] to cluster", target_host)
    
    try:
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no"})
        s.login(target_host,user_name,ssh_key=ssh_key_path,check_local_ip=False)
        s.sendline('sudo /tmp/prepare-k8s-service.sh')
        s.sendline("sudo " + join_string)
        s.prompt()
        while not 'node has joined the cluster' in s.before.decode():
            sleep(3)
            s.prompt()
            
        log.info("K8S Minion [%s] initialized", target_host)
    except (ExceptionPxssh, EOF):
        log.info("Could not connect to K8S Node [%s]", target_host)
        raise ValueError("Something went wrong during node creation")

def initialize_k8s_master(target_host, user_name, ssh_key_path):
    log.info("Initializing K8s Master [%s]", target_host)
    try:
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no"})
        s.login(target_host,user_name,ssh_key=ssh_key_path,check_local_ip=False)
        s.sendline('sudo /tmp/prepare-k8s-service.sh')
        s.sendline('sudo kubeadm init --apiserver-advertise-address=$(ifconfig eth0|grep -Po \'inet [0-9.]+\'|grep -Po \'[0-9.]+\') --pod-network-cidr=10.244.0.0/16')
        s.prompt()
        s.sendline('tail -n 2 /tmp/k8s-init.log')
        s.prompt()
        
        while not 'kubeadm join' in s.before.decode():
            sleep(3)
            s.prompt()
            s.sendline('tail -n 2 /tmp/k8s-init.log')
            
        response = s.before.decode().split('\r\n')
        response = [x for x in response if 'kubeadm join' in x ]
        cluster_join_string = response[0].strip()
        s.sendline('/tmp/initialize-k8s-cluster.sh')
        s.prompt()
        
        while not 'kube-flannel-ds-s390x created' in s.before.decode():
            sleep(3)
            s.prompt()
        
        return cluster_join_string
        
    except (ExceptionPxssh, EOF):
        raise ValueError("Could not connect to host, %s", n)
    
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


def add_sec_rule_azure(session, resource_group, sec_group_name,
                       security_rule_name, security_rule_parameters):
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


def list_sizes_aws(session, cpu_min=2, cpu_max=16, mem_min=4096, mem_max=32768,
                   disk_min=0, disk_max=0):
    sizes = session.list_sizes()
    machines = [
        x for x in sizes
        if mem_min <= x.ram <= mem_max
        and cpu_min <= int(x.extra['vcpu']) <= cpu_max
        and disk_min <= x.disk <= disk_max
    ]
    return machines


def list_sizes_azure(session, cpu_min=2, cpu_max=16, mem_min=4096,
                     mem_max=32768, disk_min=0, disk_max=10475520):
    sizes = session.list_sizes()
    machines = [
        x for x in sizes
        if mem_min <= x.ram <= mem_max
        and cpu_min <= x.extra['numberOfCores'] <= cpu_max
        and disk_min <= x.disk <= disk_max
    ]
    return machines


def list_sizes_gce(session, location=None, cpu_min=2, cpu_max=16,
                   mem_min=4096, mem_max=32768, disk_min=0, disk_max=10475520):
    sizes = session.list_sizes(location=location)
    machines = [
        x for x in sizes
        if mem_min <= x.ram <= mem_max
        and cpu_min <= x.extra['guestCpus'] <= cpu_max
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
    provider = config.profile.get('platform')['provider']
    if provider == 'GCE':
        sec_groups = session.ex_list_firewalls()
    else:
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
    log.info("Fetching Nodes matching filters in current session")
    nodes = session.list_nodes()
    if not filters:
        return nodes
    for key, val in filters.items():
        nodes = [
            x for x in nodes
            if val in utils.get_val(x, key)
        ]
    return nodes


def list_all_aws_nodes(region_list=None):
    log.info("Fetching descriptions of all nodes in all AWS Regions."
             " This will be slow...")
    b3 = create_boto3_session()
    ec2 = b3.client('ec2')
    if region_list:
        regions = region_list
    else:
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


def get_aws_network(session, create=True):
    # https://gist.github.com/nguyendv/8cfd92fc8ed32ebb78e366f44c2daea6
    log.info("Requesting VPC for Whoville")
    networks = list_networks(session, {'name': _horton.namespace})
    if not networks:
        if create is True:
            log.info("VPC not found, creating new VPC")
            vpc = session.ex_create_network(
                cidr_block='10.0.0.0/16',
                name=_horton.namespace + 'whoville'
            )
            if not vpc:
                raise ValueError("Could not create new VPC")
            networks = list_networks(session, {'name': _horton.namespace})
            if not networks or networks[0].extra['state'] != 'available':
                log.info("Waiting for new VPC to be available")
                sleep(5)
            vpc = networks[0]
            log.info("Creating Internet Gateway for VPC")
            ig = session.ex_create_internet_gateway(
                name=_horton.namespace + 'whoville'
            )
            ig_result = session.ex_attach_internet_gateway(
                gateway=ig,
                network=vpc
            )
            if not ig_result:
                raise ValueError("Could not attach internet gateway to VPC")
            log.info("Creating Route Table for VPC")
            rt = session.ex_create_route_table(
                network=vpc,
                name=_horton.namespace + 'whoville'
            )
            if not rt:
                raise ValueError("Could not create Route Table")
            log.info("Setting default route for Route Table")
            route = session.ex_create_route(
                route_table=rt,
                cidr='0.0.0.0/0',
                internet_gateway=ig
            )
            if not route:
                raise ValueError("Could not create Route for Route Table")
            log.info("Creating Subnet in VPC")
            zones = session.ex_list_availability_zones()
            subnet = session.ex_create_subnet(
                cidr_block='10.0.1.0/24',
                vpc_id=vpc.id,
                name=_horton.namespace + 'whoville',
                availability_zone=zones[-1].name
            )
            if not subnet:
                raise ValueError("Could not create Subnet on EC2")
            log.info("Associating Subnet with Route Table")
            subnet_result = session.ex_associate_route_table(
                route_table=rt,
                subnet=subnet
            )
            if not subnet_result:
                raise ValueError("Failed to associate subnet with Route Table")
            log.info("Fixing up DNS")
            ec2 = boto3.resource(
                'ec2',
                region_name=config.profile['platform']['region']
            )
            s_boto3 = create_boto3_session()
            ec2client = s_boto3.client('ec2')
            ec2client.modify_vpc_attribute(
                VpcId=vpc.id,
                EnableDnsSupport={'Value': True})
            ec2client.modify_vpc_attribute(
                VpcId=vpc.id,
                EnableDnsHostnames={'Value': True})
            log.info("Fixing up auto IP assignment")
            ec2client.modify_subnet_attribute(
                SubnetId=subnet.id,
                MapPublicIpOnLaunch={"Value": True}
            )
            log.info('Returning new VPC/Subnet')
            return list_networks(session, {'name': _horton.namespace})[-1], subnet
        else:
            log.info("VPC not found, Create is False, returning None/None")
            return None, None
    else:
        log.info("VPC found, returning VPC/Subnet")
        network = networks[-1]
        subnets = list_subnets(session, {'extra.vpc_id': network.id})
        subnets = sorted(subnets, key=lambda k: k.state)
        return network, subnets[-1]


def delete_aws_network(network_id, force=False):
    # WIP - still issues with dependencies in some cases
    b3session = create_boto3_session()
    ec2 = b3session.resource('ec2')
    ec2client = ec2.meta.client
    if not force:
        log.info("Attempting unforced delete of VPC %s", network_id)
        result = ec2client.delete_vpc(VpcId=network_id)
    else:
        # applying prejudice...
        # https://gist.github.com/alberto-morales/b6d7719763f483185db27289d51f8ec5
        vpc = ec2.Vpc(network_id)
        # detach default dhcp_options if associated with the vpc
        log.info("Attempting FORCED delete of VPC %s", network_id)
        # detach and delete all gateways associated with the vpc
        log.info("Trashing IGW setup")
        for gw in vpc.internet_gateways.all():
            vpc.detach_internet_gateway(InternetGatewayId=gw.id)
            gw.delete()
        # delete all route table associations
        log.info("Trashing RT setup")
        for rt in vpc.route_tables.all():
            for rta in rt.associations:
                if not rta.main:
                    rta.delete()
        # delete any instances
        log.info("Trashing Subnet setup")
        for subnet in vpc.subnets.all():
            for instance in subnet.instances.all():
                instance.terminate()
        # delete our endpoints
        log.info("Trashing Endpoints setup")
        for ep in ec2client.describe_vpc_endpoints(
                Filters=[{
                    'Name': 'vpc-id',
                    'Values': [network_id]
                }])['VpcEndpoints']:
            ec2client.delete_vpc_endpoints(
                VpcEndpointIds=[ep['VpcEndpointId']])
        # delete our security groups
        log.info("Trashing Security Groups setup")
        for sg in vpc.security_groups.all():
            if sg.group_name != 'default':
                sg.delete()
        # delete any vpc peering connections
        log.info("Trashing VPC Pairings")
        for vpcpeer in ec2client.describe_vpc_peering_connections(
                Filters=[{
                    'Name': 'requester-vpc-info.vpc-id',
                    'Values': [network_id]
                }])['VpcPeeringConnections']:
            ec2.VpcPeeringConnection(
                vpcpeer['VpcPeeringConnectionId']).delete()
        # delete non-default network acls
        log.info("Trashing non-default Network ACLs")
        for netacl in vpc.network_acls.all():
            if not netacl.is_default:
                netacl.delete()
        # delete network interfaces
        log.info("Trashing Network Interfaces")
        for subnet in vpc.subnets.all():
            for interface in subnet.network_interfaces.all():
                interface.delete()
            subnet.delete()
        log.info("Handling DHCP")
        dhcp = vpc.dhcp_options
        dhcp_id = dhcp.id
        dhcp_options_default = ec2.DhcpOptions('default')
        if dhcp_options_default:
            dhcp_options_default.associate_with_vpc(
                VpcId=vpc.id
            )
        if dhcp_id == 'default':
            log.info("DHCP is default, skipping trash process")
        else:
            log.info("Trashing DHCP setup %s", dhcp_id)
            dhcp.delete()
        # finally, delete the vpc
        log.info("Trashing VPC")
        try:
            result = ec2client.delete_vpc(VpcId=network_id)
        except:
            log.error("Couldn't delete VPC, please clean up in AWS Console")
    return result


def get_aws_node_summary(node_list=None):
    # ToDo: https://wiki.hortonworks.com/pages/viewpage.action?spaceKey=SE&title=Manual+Cloud+Cleanup+Procedure
    summary = []
    node_list = node_list if node_list else list_all_aws_nodes()
    [[summary.append(
        {p: q for p, q in y.items() if p in ['InstanceId', 'Placement',
                                             'State', 'Tags']})
      for y in x['Instances']] for x in node_list]
    return summary


def aws_terminate_by_tag(key_match, node_summary=None, also_terminate=False):
    ns = node_summary if node_summary else get_aws_node_summary()
    tagged = [x for x in ns if 'Tags' in x.keys()]
    matching = [x for x in tagged if key_match in str(x['Tags'][0])]
    b3 = create_boto3_session()
    for instance in matching:
        i = instance['InstanceId']
        if instance['State']['Name'] in ['running', 'pending', 'stopping',
                                         'stopped']:
            log.info("Handling Instance %s", i)
            try:
                ec2 = b3.client(
                    'ec2', instance['Placement']['AvailabilityZone'][:-1])
                log.info("Removing Termination Protection on %s", i)
                ec2.modify_instance_attribute(
                    InstanceId=i,
                    DisableApiTermination={'Value': False}
                )
            except ClientError as e:
                raise e
            if also_terminate:
                try:
                    log.info("Attempting termination of %s", i)
                    ec2.terminate_instances(InstanceIds=[i])
                except ClientError as e:
                    log.info("Couldn't terminate %s", i)
        else:
            log.info("Instance %s already killed", i)


def nuke_namespace(dry_run=True):
    provider = config.profile.get('platform')['provider']
    namespace=_horton.namespace
    if provider == 'GCE':
        # Cloudbreak creates vms with the - stripped from the name for some reason
        namespace = namespace.replace('-', '')
    log.info("Nuking all nodes in Namespace %s", namespace)
    log.info("dry_run is %s", str(dry_run))
    session = create_libcloud_session()
    all_instances = list_nodes(session, {'name': namespace})
    if not all_instances:
        log.info("No nodes matching Namespace found")
    else:
        instances = [
            x for x in all_instances
            if x.state != 'terminated'
        ]
        log.info("Destroying nodes: %s", ", ".join(x.name for x in instances))
        if provider == 'GCE':
            session.ex_destroy_multiple_nodes(instances, ignore_errors=True, destroy_boot_disk=True, poll_interval=2, timeout=180)
        else:
            for i in instances:
                log.info("Destroying Node %s", i.name)
                if not dry_run:
                    session.destroy_node(i)
            while [x for x in list_nodes(session, {'name': _horton.namespace})
                   if x.state != 'terminated']:
                log.info("Waiting for nodes to be terminated (sleep10)")
                sleep(10)

    sec_groups = list_security_groups(session, {'name': _horton.namespace})
    if not sec_groups:
        log.info("No Security Groups matching Namespace found")
    else:
        log.info("Found %s Security Group in this Namespace",
                 str(len(sec_groups)))
        for i in sec_groups:
            if provider == 'GCE':
                log.info("Destroying firewall %s", i.name)
                if not dry_run:
                    session.ex_destroy_firewall(i)
            else:
                log.info("Destroying Security Group %s", i.name)
                if not dry_run:
                    session.ex_delete_security_group_by_id(group_id=i.id)
