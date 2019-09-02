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
import libcloud.security
from botocore.exceptions import ClientError
from azure.common.credentials import ServicePrincipalCredentials
import adal
import boto3
from whoville import config, utils, security
import base64

__all__ = ['create_libcloud_session', 'create_boto3_session', 'get_cloudbreak', 'get_k8s_join_string',
           'deploy_instances', 'add_sec_rule_to_ec2_group', 'get_k8svm', 'initialize_k8s_minion',
           'create_node', 'list_images', 'list_sizes_aws', 'list_networks', 'initialize_k8s_master',
           'list_subnets', 'list_security_groups', 'list_keypairs', 'list_nodes', 'nuke_namespace',
           'aws_get_static_ip', 'resolve_firewall_rules', 'ops_get_security_group', 'ops_get_ssh_key',
           'list_sizes_ops', 'ops_get_hosting_infra', 'ops_define_base_machine', 'define_userdata_script',
           'aws_clean_stacks', 'delete_aws_network', 'aws_get_ssh_key', 'aws_get_hosting_infra']

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# ADAL for Azure is verbose, reducing output
adal.log.set_logging_options({'level': 'WARNING'})

horton = utils.Horton()


def create_libcloud_session():
    provider = config.profile.get('platform')['provider']
    cls = get_driver(getattr(Provider, provider))
    params = config.profile.get('platform')
    if not params:
        raise ValueError("Profile not configured with Platform Parameters")
    if provider == 'EC2':
        return cls(
                **{x: y for x, y in params.items() if x in ['key', 'secret', 'region']}
            )
    elif provider == 'AZURE_ARM':
        return cls(tenant_id=params['tenant'],
                   subscription_id=params['subscription'],
                   key=params['application'],
                   secret=params['secret'],
                   region=params['region'])
    elif provider == 'GCE':
        return cls(params['serviceaccount'],
                   params['apikeypath'],
                   project=params['project'])
    elif provider == 'OPENSTACK':
        # As this is accessible ONLY over VPN, I feel less concerned about MITM attacks
        # TODO: Get Proper certs for Openstack
        # https://buildmedia.readthedocs.org/media/pdf/libcloud/v2.4.0/libcloud.pdf
        # search 'libcloud.security
        libcloud.security.VERIFY_SSL_CERT = params['verify_ssl']
        if params['verify_ssl'] is True and 'cacert_path' in params and params['cacert_path']:
            libcloud.security.CA_CERTS_PATH = params['cacert_path']
        # This works for Openstack keystone v3
        return cls(
            params['username'],
            params['password'],
            ex_tenant_name=params['project'],
            ex_force_auth_url=params['auth_url'],
            ex_force_auth_version=params['auth_mode']
        )
    else:
        raise ValueError("Provider %s not Supported", provider)


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
    if service == 'storage':
        from azure.mgmt.storage import StorageManagementClient
        return StorageManagementClient(token, sub_id)
    if service == 'resource':
        from azure.mgmt.resource import ResourceManagementClient
        return ResourceManagementClient(token, sub_id)


def get_cloudbreak(s_libc=None, create=True, purge=False, create_wait=0):
    if not s_libc:
        s_libc = create_libcloud_session()

    cbd_name = horton.namespace + 'cloudbreak'
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
            cbd = deploy_instances(s_libc, [cbd_name], mode='cb', assign_ip=True)
            log.info("Waiting for Cloudbreak Deployment to Complete")
            if s_libc.type == 'openstack':
                cbd_fqdn = cbd[cbd_name].name + config.profile['platform']['domain']
            else:
                cbd_fqdn = cbd[cbd_name].public_ips[0]
            utils.wait_to_complete(
                utils.is_endpoint_up,
                'https://' + cbd_fqdn,
                whoville_delay=30,
                whoville_max_wait=600
            )
            return cbd[cbd_name]


def get_k8svm(s_libc=None, create=True, purge=False, create_wait=0):
    s_libc = s_libc if s_libc else create_libcloud_session()
    # Work out instance counts and names
    k8s_master_name = horton.namespace + 'k8s-master'
    k8s_minion_basename = horton.namespace + 'k8s-minion-'
    num_workers = config.profile['k8s_workers'] if 'k8s_workers' in config.profile else 3
    minion_names = [
        k8s_minion_basename + str(x) for x in range(num_workers)
    ]
    instances_to_create = []
    # check for existing instances
    k8s_master = [
        x for x
        in list_nodes(s_libc, {'name': k8s_master_name})
        if x.state == 'running'
    ]
    k8s_minions = [
        x for x
        in list_nodes(s_libc, {'name': k8s_minion_basename})
        if x.state == 'running'
    ]
    # working out what to create and destroy
    if k8s_master:
        log.info("Existing K8s master instance found")
        if purge:
            log.info("K8S Master found, Purge is True, destroying Master and Minions...")
            [s_libc.destroy_node(x) for x in [k8s_master, k8s_minions]]
            instances_to_create.append(k8s_master_name)
            instances_to_create += minion_names
        else:
            log.info("Purge not set, adding existing K8svm Master to Horton Borgleton")
            horton.k8svm[k8s_master_name] = k8s_master
            if k8s_minions:
                log.info("Purge not set, found [%d] existing minions", len(k8s_minions))
                minions_to_create = [
                    x for x in minion_names if x not in [y.name for y in k8s_minions]
                ]
                log.info("Creating [%d] additional K8s minions", len(minions_to_create))
                instances_to_create += minions_to_create
                for minion in k8s_minions:
                    horton.k8svm[minion.name] = minion
            else:
                log.info("Creating [%d] additional K8s minions", len(minion_names))
                instances_to_create += minion_names
    else:
        instances_to_create.append(k8s_master_name)
        instances_to_create += minion_names
    # getting on with it
    if not instances_to_create:
        log.info("Found K8sVM environment with enough workers, returning...")
    else:
        if not create:
            raise ValueError("Instances missing from manifest but Create not set, bailing...")
        # run create instances
        log.info("K8sVM environment needs the following instances deployed [%s]", str(instances_to_create))
        if create_wait > 0:
            log.warning("About to deploy new instances! waiting [%d] seconds for abort...", create_wait)
        instances = deploy_instances(s_libc, instances_to_create, mode='k8svm', assign_ip=False)
        log.info("Waiting for K8s instances to be available")
        for i in instances.keys():
            log.info("Checking for connectivity to [%s] on [%s]", instances[i].public_ips[0])
            utils.wait_to_complete(
                utils.get_remote_shell,
                target_host=instances[i].public_ips[0],
                wait=False,
                whoville_delay=30,
                whoville_max_wait=600
            )
        log.info("Checking K8s instances for userdata script success")
        for i in instances.keys():
            log.info("Checking userdata success on [%s]", i)
            utils.wait_to_complete(
                utils.execute_remote_cmd,
                target_host=instances[i].public_ips[0],
                cmd='cat /tmp/status.success',
                expect='complete',
                bool_response=True,
                whoville_delay=30,
                whoville_max_wait=600
            )
        # Setup K8s on machines
        if k8s_master_name in horton.k8svm.keys():
            # if already in horton then K8s cluster should be created
            horton.cache['KUBEADMJOIN'] = get_k8s_join_string(horton.k8svm[k8s_master_name].public_ips[0])
        else:
            # need to grab the master node we must've just deployed and init it
            horton.cache['KUBEADMJOIN'] = initialize_k8s_master(instances[k8s_master_name].public_ips[0])
            horton.k8svm[k8s_master_name] = instances[k8s_master_name]
        for i in instances.keys():
            if k8s_master_name not in instances[i].name:
                # if not master, then add to cluster as worker
                initialize_k8s_minion(instances[i].public_ips[0], horton.cache['KUBEADMJOIN'])
                horton.k8svm[instances[i].name] = instances[i].name
    log.info("K8s IaaS Cluster deployment complete")
    return horton.k8svm


def get_k8s_join_string(target_host):
    log.info("Fetching new Kubeadm join string and token from K8s VM cluster")
    r = utils.execute_remote_cmd(target_host,
                                 'sudo kubeadm token create --print-join-command',
                                 'kubeadm join',
                                 False)
    cluster_join_string = [x for x in r.split('\r\n') if 'kubeadm join' in x][0].strip()
    return cluster_join_string


def aws_clean_stacks(s_boto3):
    client_cf = s_boto3.client('cloudformation')
    client_as = s_boto3.client('autoscaling')
    log.info("Lising Cloudformation Stacks in Namespace")
    cf_stacks = [x for x in client_cf.list_stacks()['StackSummaries']
                 if x['StackName'].startswith(horton.namespace)
                 and x['StackStatus'] != 'DELETE_COMPLETE']
    log.info("Listing Autoscaling groups in Namespace")
    as_stacks = [x for x in client_as.describe_auto_scaling_groups()['AutoScalingGroups']
                 if x['AutoScalingGroupName'].startswith(horton.namespace)]
    for cf_stack in cf_stacks:
        log.info("Found Cloud Formation [%s], deleting to avoid "
                 "collision with Cloudbreak cluster creation...",
                 cf_stack['StackName'])
        client_cf.delete_stack(
            StackName=cf_stack['StackName']
        )
    for as_stack in as_stacks:
        log.info("Found AutoScalingGroup [%s], deleting to clean up estate",
                 as_stack['AutoScalingGroupName'])
        client_as.delete_auto_scaling_group(
            AutoScalingGroupName=as_stack['AutoScalingGroupName'],
            ForceDelete=True
        )
    log.info("Done with AWS Stack Cleanup tasks")


def initialize_k8s_minion(target_host, join_string):
    log.info("Joining K8S Minion [%s] to cluster", target_host)
    _ = utils.execute_remote_cmd(target_host, 'sudo /tmp/prepare-k8s-service.sh', None, False)
    _ = utils.execute_remote_cmd(target_host, "sudo " + join_string, 'node has joined the cluster', False)
    log.info("K8S Minion [%s] initialized", target_host)


def initialize_k8s_master(target_host):
    log.info("Initializing K8s Master [%s]", target_host)
    _ = utils.execute_remote_cmd(target_host, 'sudo /tmp/prepare-k8s-service.sh', None, False)
    _ = utils.execute_remote_cmd(target_host,'sudo kubeadm init --apiserver-advertise-address=$(hostname -I | awk \'{print $1}\') --pod-network-cidr=10.244.0.0/16  > /tmp/k8s-init.log',
                                 None,
                                 False
                                 )
    r = utils.execute_remote_cmd(target_host, 'tail -n 2 /tmp/k8s-init.log', 'kubeadm join', True)
    cluster_join = r.split('\n')
    cluster_join = [x for x in cluster_join
                    if 'kubeadm join' in x 
                    or '--discovery-token-ca-cert-hash' in x]
    cluster_join_string = ' '.join(cluster_join).replace('\\','').replace('\r','').strip()
    _ = utils.execute_remote_cmd(target_host, '/tmp/initialize-k8s-cluster.sh', 'kube-flannel-ds-s390x created', False)
    log.info("K8s Master init complete")
    return cluster_join_string


def add_sec_rule_to_ops_group(session, rule, sec_group):
    log.info("Attempting to create rule with [%s]", str(rule))
    # Openstack doesn't support 'any' when passed via the API client apparently
    protocol = rule['protocol'] if rule['protocol'] != -1 else 'tcp'
    for cidr in rule['cidr_ips']:
        try:
            session.ex_create_security_group_rule(
                security_group=sec_group,
                ip_protocol=protocol,
                from_port=rule['from_port'],
                to_port=rule['to_port'],
                cidr=cidr
            )
        except BaseHTTPError as e:
            if 'This rule already exists' in e.message:
                pass
            else:
                raise e


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
def create_node(session, name, image, machine, params=None):
    obj = {
        'name': name,
        'image': image,
        'size': machine,
        **params
    }
    node = session.create_node(**obj)
    log.info("Waiting for node to be Available...")
    if session.type == 'openstack':
        # Private OpenStack uses Private IPs, not public
        session.wait_until_running(
            nodes=[node],
            ssh_interface='private_ips'
        )
    else:
        session.wait_until_running(nodes=[node])
    return node


def list_images(session, filters):
    return session.list_images(ex_filters=filters)


def list_sizes_aws(session, cpu_min=2, cpu_max=16, mem_min=4096, mem_max=32768,
                   disk_min=0, disk_max=0):
    # todo: refactor
    sizes = session.list_sizes()
    machines = [
        x for x in sizes
        if mem_min <= x.ram <= mem_max
        and cpu_min <= int(x.extra['vcpu']) <= cpu_max
        and disk_min <= x.disk <= disk_max
    ]
    return machines


def list_sizes_ops(session, cpu_min=2, cpu_max=16, mem_min=4096,
                   mem_max=32768):
    sizes = session.list_sizes()
    return [
        x for x in sizes
        if mem_min <= x.ram <= mem_max
        and cpu_min <= x.vcpus <= cpu_max
    ]


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
    elif provider == 'OPENSTACK':
        sec_groups = session.ex_list_security_groups()
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
    networks = list_networks(session, {'name': horton.namespace})
    if not networks:
        if create is True:
            log.info("VPC not found, creating new VPC")
            vpc = session.ex_create_network(
                cidr_block='10.0.0.0/16',
                name=horton.namespace + 'whoville'
            )
            if not vpc:
                raise ValueError("Could not create new VPC")
            networks = list_networks(session, {'name': horton.namespace})
            if not networks or networks[0].extra['state'] != 'available':
                log.info("Waiting for new VPC to be available")
                sleep(5)
            vpc = networks[0]
            log.info("Creating Internet Gateway for VPC")
            ig = session.ex_create_internet_gateway(
                name=horton.namespace + 'whoville'
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
                name=horton.namespace + 'whoville'
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
            if 'zone' in config.profile['platform']:
                preferred_az_name = config.profile['platform']['region'] + config.profile['platform']['zone']
                try:
                    az = [
                        x.name for x in zones
                        if x.name == preferred_az_name
                    ][0]
                except:
                    az = zones[0].name
            else:
                az = zones[0].name
            subnet = session.ex_create_subnet(
                cidr_block='10.0.1.0/24',
                vpc_id=vpc.id,
                name=horton.namespace + 'whoville',
                availability_zone=az
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
            return list_networks(session, {'name': horton.namespace})[-1], subnet
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
    namespace = horton.namespace
    if provider == 'GCE':
        # Cloudbreak creates vms with the - stripped from the name for some reason
        namespace = namespace.replace('-', '')
    log.info("Nuking all nodes in Namespace %s", namespace)
    log.info("dry_run is %s", str(dry_run))
    session = create_libcloud_session()
    log.info("Fetching list of nodes in Namespace")
    all_instances = list_nodes(session, {'name': namespace})
    if not all_instances:
        log.info("No nodes matching Namespace found")
    else:
        instances = [
            x for x in all_instances
            if x.state != 'terminated'
        ]
        log.info("Destroying nodes: %s", ", ".join(x.name for x in instances))
        log.info("May take as long as 10 minutes to complete.")
        if not dry_run:
            if provider == 'GCE':
                session.ex_destroy_multiple_nodes(instances, ignore_errors=True, destroy_boot_disk=True, poll_interval=2, timeout=600)
            else:
                for i in instances:
                    log.info("Destroying Node %s", i.name)
                    session.destroy_node(i)
                while [x for x in list_nodes(session, {'name': horton.namespace})
                       if x.state != 'terminated']:
                    log.info("Waiting for nodes to be terminated (sleep10)")
                    sleep(10)
        else:
            for i in instances:
                log.info("Dry Run: Would be deleting node %s", i.name)

    sec_groups = list_security_groups(session, {'name': horton.namespace})
    if not sec_groups:
        log.info("No Security Groups matching Namespace found")
    else:
        log.info("Found %s Security Group in this Namespace",
                 str(len(sec_groups)))
        if not dry_run:
            for i in sec_groups:
                if provider == 'GCE':
                    log.info("Destroying firewall %s", i.name)
                    if not dry_run:
                        session.ex_destroy_firewall(i)
                elif provider == 'OPENSTACK':
                    session.ex_delete_security_group(i)
                else:
                    log.info("Destroying Security Group %s", i.name)
                    if not dry_run:
                        session.ex_delete_security_group_by_id(group_id=i.id)
        else:
            for i in sec_groups:
                log.info("Dry Run: Would be destoying security group %s", i.name)
    if provider == 'EC2':
        if not dry_run:
            aws_clean_stacks(create_boto3_session())
        else:
            log.info("Dry Run: Would be cleaning AWS Stacks")
    elif provider=='GCE':
        for address in [
            x for x in session.ex_list_addresses(region=config.profile.get('platform')['region'])
            if x.name.startswith(namespace)
        ]:
            log.info("Destroying address [%s]", address.name)
            session.ex_destroy_address(address)


def resolve_firewall_rules():
    log.info("Checking local public IP")
    try:
        my_public_ip = requests.get('https://ipv4.icanhazip.com', timeout=3).text.rstrip()
    except:
        my_public_ip = requests.get('https://ifconfig.me/ip', timeout=3).text.rstrip()
    log.info("Deploying User Public IP is %s, using for Firewall rules", my_public_ip)
    # Defaults
    net_rules = config.default_net_rules
    # Add deployment user
    net_rules.append(
        {
            'protocol': -1,  # initiators public IP
            'from_port': 1,
            'to_port': 65535,
            'cidr_ips': [my_public_ip + '/32'],
            'description': 'DeployerConnect'
        }
    )
    # Process whitelist
    if 'cidr_whitelist' in config.profile:
        for whitelist_cidr in config.profile['cidr_whitelist']:
            net_rules.append(
                {
                    'protocol': -1,
                    'cidr_ips': [whitelist_cidr],
                    'from_port': 1,
                    'to_port': 65535,
                    'description': 'fromProfileWhitelist'
                }
            )
    return net_rules


def ops_define_base_machine(session):
    log.info("Finding Machine Image")
    # OpenStack's list images call doesn't support filters
    images = [
        x for x in session.list_images()
        if 'CentOS 7.' in x.name
    ]
    image = sorted(images, key=lambda k: k.extra['created'])
    if not image:
        raise ValueError("Couldn't find a valid Centos7 Image")
    else:
        image = image[-1]
    # No Disk specification available?
    machines = list_sizes_ops(
        session, cpu_min=8, cpu_max=8, mem_min=15000, mem_max=20000
    )
    if not machines:
        raise ValueError("Couldn't find a VM of the right size")
    else:
        machine = machines[-1]
    return image, machine


def aws_define_base_machine(session):
    log.info("Finding an appropriate base machine for AWS deployment")
    log.info("Selecting OS Image")
    raw_images = list_images(
        session,
        filters={
            'name': '*CentOS Linux 7 x86_64 HVM EBS ENA*',
        }
    )
    # Limit to AWS Marketplace images from Centos owner only
    official_images = [
        x for x in raw_images
        if '679593333241' in x.extra['owner_id']
    ]
    image = sorted(official_images, key=lambda k: k.extra['description'][-7:])
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
        return image, root_vol, machine


def ops_get_security_group(session):
    # OpenStack default is a flat network, do not need complex firewall setup
    # log.info("Resolving Firewall Rules")
    # net_rules = resolve_firewall_rules()
    log.info("Fetching Security groups matching namespace")
    sec_group = list_security_groups(session, {'name': horton.namespace})
    if not sec_group:
        log.info("Namespace Security group not found, creating")
        _ = session.ex_create_security_group(
            name=horton.namespace + 'whoville',
            description=horton.namespace + 'whoville Security Group'
        )
        sec_group = list_security_groups(session, {'name': horton.namespace})[-1]
    else:
        sec_group = sec_group[-1]
        log.info("Found existing Security Group %s", sec_group.name)
        log.info("Ensuring Security Group has required Network Rules")
    # Blanket inbound rule as environment is isolated
    net_rules = [
        {
            'protocol': 'tcp',
            'cidr_ips': ['0.0.0.0/0'],
            'from_port': 1,
            'to_port': 65535
        }
    ]
    for rule in net_rules:
        add_sec_rule_to_ops_group(session, rule, sec_group)
    log.info("Security Group preparation complete, returning to main program")
    return list_security_groups(session, {'name': horton.namespace})[-1]


def aws_get_security_group(session, vpc, subnet):
    log.info("Resolving Firewall Rules")
    net_rules = resolve_firewall_rules()
    log.info("Fetching Security groups matching namespace")
    sec_group = list_security_groups(session, {'name': horton.namespace})
    if not sec_group:
        log.info("Namespace Security group not found, creating")
        _ = session.ex_create_security_group(
            name=horton.namespace + 'whoville',
            description=horton.namespace + 'whoville Security Group',
            vpc_id=vpc.id
        )
        sec_group = list_security_groups(session, {'name': horton.namespace})[-1]
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
        try:
            add_sec_rule_to_ec2_group(session, rule, sec_group.id)
        except BaseHTTPError:
            sleep(3)
            add_sec_rule_to_ec2_group(session, rule, sec_group.id)
    return list_security_groups(session, {'name': horton.namespace})[-1]


def ops_get_ssh_key(session):
    ssh_key = [
        x for x in session.ex_list_keypairs()
        if config.profile['sshkey_name'] in x.name
    ]
    if not ssh_key:
        ssh_key = session.ex_import_key_pair_from_string(
            name=config.profile['sshkey_name'],
            key_material=config.profile['sshkey_pub']
        )
    else:
        ssh_key = [x for x in ssh_key
                   if x.name == config.profile['sshkey_name']][0]
    return ssh_key


def aws_get_ssh_key(session):
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
                   if x.name == config.profile['sshkey_name']]
    if not ssh_key:
        raise ValueError("SSH Key named [%s] not found in AWS Key Listing", config.profile['sshkey_name'])
    try:
        return ssh_key[0]
    except TypeError:
        return ssh_key


def aws_get_static_ip(session):
    log.info("Fetching list of available Static IPs")
    try:
        static_ips = [
            x for x in session.ex_describe_all_addresses()
            if not x.instance_id
            and x.extra['association_id'] is None
            and x.extra['allocation_id'] is not None
        ]
    except InvalidCredsError:
        static_ips = None
    if not static_ips:
        log.info("Available Static IP not found, Allocating new")
        static_ip = session.ex_allocate_address(domain='vpc')
    else:
        log.info("Found available Static IPs, using first available")
        static_ip = static_ips[0]
    if not static_ip:
        raise ValueError("Couldn't get a Static IP")
    return static_ip


def define_userdata_script(mode='cb', static_ip=None):
    if mode == 'cb':
        log.info("Checking for Cloudbreak Version override")
        cb_ver = config.profile.get('cloudbreak_ver')
        cb_ver = str(cb_ver) if cb_ver else config.cb_ver
        log.info("Checking for FQDN to use in userdata script")

        # this allows direct passthrough if not an IP from EC2-like setups
        if 'ElasticIP' in str(type(static_ip)):
            fqdn = static_ip.ip
        elif 'GCEAddress' in str(type(static_ip)):
            fqdn = static_ip.address
        elif 'domain' in config.profile['platform']:
            fqdn = static_ip + config.profile['platform']['domain']
        else:
            raise ValueError("Static IP or FQDN domain must be available to proceed")
        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "export cb_ver=" + cb_ver,
            "export uaa_secret=" + security.get_secret('MASTERKEY'),
            "export uaa_default_pw=" + security.get_secret('ADMINPASSWORD'),
            "export uaa_default_email=admin@example.com",
            "export public_ip=" + fqdn,
            "source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
            "/whoville/master/bootstrap/v2/cbd_bootstrap_centos7.sh)"
        ]
    elif mode == 'k8svm':
        script_lines = [
            "#!/bin/bash",
            "cd /root",
            "if [ -f /tmp/status.success ]; then",
            "    exit",
            "else",
            "    source <(curl -sSL https://raw.githubusercontent.com/Chaffelson"
            "/whoville/master/bootstrap/v2/k8svm_bootstrap_centos7.sh)",
            "fi"
        ]
    else:
        raise ValueError("Mode [%s] not recognised", mode)
    return '\n'.join(script_lines)


def aws_assign_static_ip(session, node, static_ip):
    log.info("Associating Static IP to Instance")
    try:
        log.info("Attempting standard IP Association")
        session.ex_associate_address_with_node(
            node,
            static_ip
        )
        log.info("Succeeded with Standard IP Association, we are probably not on EC2-Classic")
    except (BaseHTTPError, InvalidCredsError) as e:
        if 'InvalidParameterCombination' in e.message:
            log.info("Attempting failback IP Association for legacy VPCs")
            session.ex_associate_address_with_node(
                node,
                static_ip,
                domain='vpc'  # needed for legacy AWS accounts
            )
            log.info("Succeeded with failback IP Association, we are probably on EC2-Classic")
        elif 'AuthFailure: You do not have permission' in e.message:
            raise EnvironmentError("Unable to Assign Static IP to Instance, you "
                                   "may be missing permissions or reached the "
                                   "Limit of your Static IP Allocation")
        else:
            raise e


def set_instance_tags(session, instance, tags):
    log.info("Setting Instance Tags")
    session.ex_create_tags(resource=instance, tags=tags)


def aws_get_hosting_infra(session):
    log.info("Fetching AWS network")
    vpc, subnet = get_aws_network(session)
    log.info("Fetching AWS Security Group")
    sec_group = aws_get_security_group(session, vpc, subnet)
    log.info("Checking for expected SSH Keypair")
    ssh_key = aws_get_ssh_key(session)
    return vpc, subnet, sec_group, ssh_key


def ops_get_network(session):
    network = [
        x for x in session.ex_list_networks()
        if 'PROVIDER' in x.name
    ]
    if network:
        return network[0]
    else:
        raise EnvironmentError("'PROVIDER' network not found in OpenStack")


def ops_get_hosting_infra(session):
    log.info("Fetching OpenStack Network")
    network = ops_get_network(session)
    log.info("Fetching OpenStack Security Group")
    sec_group = ops_get_security_group(session)
    log.info("Checking for expected SSH Keypair")
    ssh_key = ops_get_ssh_key(session)
    return network, sec_group, ssh_key


def deploy_instances(session, names, mode='cb', assign_ip=True):
    assert isinstance(names, list)
    if session.type == 'openstack':
        log.info("Session Type is Openstack, fetching Infrastructure information")
        network, sec_group, ssh_key = ops_get_hosting_infra(session)
        log.info("Determining default node configuration")
        image, machine = ops_define_base_machine(session)
        instances = {}
        for name in names:
            log.info("Handling instance [%s]", name)
            # We're not doing static IPs on OpenStack
            # We're using dynamic DNS ! woo
            log.info("Defining deployment userdata script")
            script = define_userdata_script(mode, static_ip=name)
            log.info("Creating Instance for [%s]", name)
            instance = create_node(
                session=session, name=name, image=image, machine=machine,
                params={
                    'ex_security_groups': [sec_group],
                    'ex_keyname': ssh_key.name,
                    'ex_userdata': script,
                    'networks': [network],
                    'ex_admin_pass': security.get_secret('ADMINPASSWORD'),
                    'ex_availability_zone': session._ex_tenant_name.upper()
                }
            )
            log.info("Instance [%s] created as [%s]", name, instance)
            instance = [x for x in list_nodes(session, {'name': name}) if x.state == 'running']
            if instance:
                log.info("Instance [%s] deploy complete...", name)
                instances[name] = instance[0]
            else:
                raise ValueError("Failed to create new Instance [%s]", name)
        return instances
    elif session.type == 'ec2':
        log.info("Session Type is ec2, fetching AWS Hosting Infrastructure")
        vpc, subnet, sec_group, ssh_key = aws_get_hosting_infra(session)
        log.info("Determining default node configuration")
        image, root_vol, machine = aws_define_base_machine(session)
        instances = {}
        for name in names:
            log.info("Handling instance [%s]", name)
            if assign_ip:
                log.info("Checking for available Static IP")
                static_ip = aws_get_static_ip(session)
            else:
                static_ip = None
            log.info("Using Static IP of [%s]", static_ip.ip)
            log.info("Defining deployment userdata script")
            script = define_userdata_script(mode, static_ip=static_ip)
            log.info("Creating Instance for [%s]", name)
            instance = create_node(
                session=session, name=name, image=image, machine=machine,
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
            tags = utils.resolve_tags(name, config.profile['tags']['owner'])
            set_instance_tags(session, instance, tags)
            log.info("Instance [%s] created as [%s]", name, instance)
            if assign_ip:
                aws_assign_static_ip(session, instance, static_ip)
            instance = [x for x in list_nodes(session, {'name': name}) if x.state == 'running']
            # The VPC is setup to always assign a public IP, but sometimes it's a bit slow
            while not instance[0].public_ips:
                sleep(3)
                instance = [x for x in list_nodes(session, {'name': name}) if x.state == 'running']
            if instance:
                log.info("Instance [%s] deploy complete...", name)
                instances[name] = instance[0]
            else:
                raise ValueError("Failed to create new Instance [%s]", name)
        return instances
    elif session.type == 'azure_arm':
        if mode == 'cb':
            name = names[0]
        ssh_key = config.profile['sshkey_pub']
        resource_group = horton.namespace + 'cloudbreak-group'
        network_name = horton.namespace + 'cloudbreak-network'
        subnet_name = horton.namespace + 'cloudbreak-subnet'
        sec_group_name = horton.namespace + 'cloudbreak-secgroup'
        public_ip_name = horton.namespace + 'cloudbreak-ip'
        nic_name = horton.namespace + 'cloudbreak-nic'
        disk_account_name = horton.namespace + 'diskaccount'
        disk_account_name = disk_account_name.replace('-', '')
        log.info("Creating Resource Group...")
        token = get_azure_token()
        azure_resource_client = create_azure_session(token, 'resource')
        azure_resource_client.resource_groups.create_or_update(
            resource_group,
            {'location': config.profile.get('platform')['region']}
        )

        image = session.list_images(
            ex_publisher='OpenLogic', ex_offer='CentOS-CI', ex_sku='7-CI'
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
        cb_ver = str(cb_ver) if cb_ver else config.cb_ver
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
        script = str(base64.urlsafe_b64encode(script)) \
            .replace("b'", "").replace("'", "")

        log.info("Creating Virtual Machine...")
        log.info("with custom_data string like: " + script[:100])
        azure_compute_client = create_azure_session(token, 'compute')
        cbd = azure_compute_client.virtual_machines.create_or_update(
            resource_group,
            name,
            {
                'location': config.profile.get('platform')['region'],
                'os_profile': {
                    'computer_name': name,
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
                        'name': name,
                        'create_option': 'fromImage',
                        'vhd': {
                            'uri': 'https://{}.blob.core.windows.net/'
                                   'vhds/{}.vhd'
                                    .format(disk_account_name, name)}
                    },
                },
                'network_profile': {
                    'network_interfaces': [{'id': nic.id, 'primary': True}]
                }
            }
        )
        log.info("Waiting for Cloudbreak Instance to be Available...")
        cbd.wait()

        cbd = list_nodes(session, {'name': name})
        cbd = [x for x in cbd if x.state == 'running']
        if cbd:
            return {name: cbd[0]}
        else:
            raise ValueError("Failed to create new Cloubreak Instance")
    elif session.type == 'gce':
        region = config.profile['platform']['region']
        name = horton.namespace + 'cloudbreak'
        public_ip_name = horton.namespace + 'cloudbreak-public-ip'
        subnet_name = horton.namespace + 'cloudbreak-subnet'
        firewall_name = horton.namespace + 'cloudbreak-firewall'
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
            if x.name == network.name
        ]
        if not subnet:
            session.ex_create_subnetwork(
                name=subnet_name, region=region, network=network
            )
        else:
            subnet = subnet[-1]
            subnet_name = subnet.name
            log.info("Found existing subnet called: " + subnet_name)

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
                 'ports': ['22', '443', '8443', '9443', '7189']
                 }
            ]
            _ = session.ex_create_firewall(name=firewall_name,
                                           network=network,
                                           allowed=net_rules,
                                           target_tags=[name])

        cb_ver = config.profile.get('cloudbreak_ver')
        cb_ver = str(cb_ver) if cb_ver else config.cb_ver

        instances = {}
        assign_ip = True
        for name in names:
            log.info("Handling instance [%s]", name)

            if assign_ip:
                log.info("Getting Public IP...")
                public_ip_name = name + '-public-ip'
                try:
                    public_ip = session.ex_get_address(
                        name=public_ip_name, region=region
                    )
                    log.info("Found existing Public IP matching name: "
                             + public_ip_name)
                except ResourceNotFoundError:
                    log.info("Creating new Public IP with name: " + public_ip_name)
                    public_ip = session.ex_create_address(
                        name=public_ip_name, region=region
                    )
                public_ip.ip = public_ip.address
            else:
                public_ip = None

            script = define_userdata_script(mode, static_ip=public_ip)

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
            tags = utils.resolve_tags(name, config.profile['tags']['owner'])
            log.info("Creating Instance for [%s]", name)
            newnode = session.create_node(
                name=name,
                size=machine,
                image=image,
                location=zone,
                ex_network=network,
                external_ip=public_ip,
                ex_metadata=metadata,
                ex_tags=[name],
                ex_labels=tags)

            log.info("Waiting for Instance [%s] to be Available...", name)
            session.wait_until_running(nodes=[newnode])
            nodes = list_nodes(session, {'name': name})
            running = [x for x in nodes if x.state == 'running']
            if running:
                log.info("Instance [%s] deploy complete...", name)
                instances[name] = running[0]
            else:
                raise ValueError("Failed to create new Instance [%s]", name)
        return instances
    else:
        raise ValueError("Session Provider [%s] not supported", session.type)
