# -*- coding: utf-8 -*-

"""
For interactions with Cloudera Altus Director

Warnings:
    Experimental, not extensively tested
"""

from __future__ import absolute_import
import logging
from time import sleep
import six
import uuid
from whoville import config, utils, security, infra
import cloudera.director.latest as cd
from cloudera.director.common.rest import ApiException

__all__ = ['list_environments', 'get_environment', 'create_environment',
           'delete_environment', 'create_deployment', 'list_deployments',
           'delete_deployment', 'get_deployment', 'get_deployment_status',
           'list_clusters', 'create_instance_template',
           'get_instance_template', 'get_cluster',
           'create_cluster', 'create_virtual_instance']

log = logging.getLogger(__name__)
horton = utils.Horton()


def get_environment(env_name=None):
    tgt_env_name = env_name if env_name else horton.namespace + 'whoville'
    envs = list_environments()
    if tgt_env_name in envs:
        env_test = cd.EnvironmentsApi(horton.cad).get_redacted(tgt_env_name)
        while not env_test:
            sleep(2)
            env_test = cd.EnvironmentsApi(horton.cad).get_redacted(tgt_env_name)
        return env_test
    else:
        return create_environment()


def list_environments(bool_response=False):
    # Using this function as a test for the Cloudbreak Api being available
    try:
        envs = cd.EnvironmentsApi(horton.cad).list()
        if not bool_response:
            return envs
        else:
            if isinstance(envs, list):
                return True
            else:
                return False
    except ApiException as e:
        if bool_response:
            return False
        else:
            raise e


def create_environment():
    platform = config.profile.get('platform')
    env_name = horton.namespace + 'whoville'
    if 'ssh_key_priv' in config.profile:
        priv_key = config.profile['ssh_key_priv']
    elif 'sshkey_priv' in config.profile:
        priv_key = config.profile['sshkey_priv']
    else:
        raise ValueError("SSH Private Key is required in your Profile, please update from the Template")
    if platform['provider'] == 'EC2':
        env_type = 'aws'
        env_config = {
                    'accessKeyId': platform['key'],
                    'secretAccessKey': platform['secret'],
                    'region': platform['region']
                }
    elif platform['provider'] == 'GCE':
        env_type = 'google'
        env_config = {
                    'projectId': platform['project'],
                    'jsonKey': platform['jsonkey'],
                    'region': platform['region']
                }
    elif platform['provider'] == 'AZURE_ARM':
        env_type = 'azure'
        env_config = {
            'clientId': env_type,
            'azureCloudEnvironment': env_type,
            'tenantId': platform['application'],
            'clientSecret': platform['secret'],
            'region': platform['region'].lower().replace(' ', ''),
            'subscriptionId': platform['subscription'],
        }
    else:
        raise ValueError("Provider %s not supported for Director in Whoville", platform['provider'])
    cad_env = cd.Environment(
        name=env_name,
        credentials=cd.SshCredentials(
            username='centos',
            port=22,
            private_key=priv_key
        ),
        provider=cd.InstanceProviderConfig(
            type=env_type,
            config=env_config
        )
    )
    try:
        cd.EnvironmentsApi(horton.cad).create(cad_env)
    except ApiException as e:
        if 'iam:GetInstanceProfile' in e.body:
            sleep(3)
            # The first attempt usually fails, then will succeed after
            cd.EnvironmentsApi(horton.cad).create(cad_env)
        else:
            raise e
    env_test = cd.EnvironmentsApi(horton.cad).get_redacted(env_name)
    while not env_test:
        sleep(2)
        env_test = cd.EnvironmentsApi(horton.cad).get_redacted(env_name)
    return env_test


def delete_environment(env_name=None):
    env_name = env_name if env_name else horton.cdcred.name
    try:
        return cd.EnvironmentsApi(horton.cad).delete(env_name)
    except ApiException as e:
        raise e


def list_deployments(env_name=None):
    env_name = env_name if env_name else horton.cdcred.name
    return cd.DeploymentsApi(horton.cad).list(environment=env_name)


def create_deployment(cm_ver, env_name=None, tem_name=None, dep_name=None,
                      tls_start=False, csds=None):
    assert isinstance(cm_ver, six.string_types)
    env_name = env_name if env_name else horton.cdcred.name
    log.info("Using Environment [%s]", env_name)
    tem_name = tem_name if tem_name else horton.cdcred.name
    log.info("Using Virtual Template [%s]", tem_name)
    dep_name = dep_name if dep_name else env_name + '-' + str(cm_ver).replace(
        '.', '-')
    template = get_instance_template(tem_name=tem_name)
    if not template:
        log.info("Template [%s] not found, creating from defaults", tem_name)
        create_instance_template(tem_name=tem_name)
        while not template:
            sleep(2)
            template = get_instance_template(tem_name=tem_name)
    if cm_ver[0] == '6':
        repo = 'https://archive.cloudera.com/cm6/' + cm_ver + '/redhat7/yum/'
        repo_key = 'https://archive.cloudera.com/cm6/' + cm_ver +\
                   '/redhat7/yum/RPM-GPG-KEY-cloudera'
    elif cm_ver[0] == '5':
        repo = 'https://archive.cloudera.com/cm5/redhat/7/x86_64/cm/' +\
               cm_ver + '/'
        repo_key = 'https://archive.cloudera.com/cm5/redhat/7/x86_64/cm/' \
                   'RPM-GPG-KEY-cloudera'
    else:
        raise ValueError("Only CM 5 or 6 supported")
    try:
        log.info("Attempting to create Deployment [%s]", dep_name)
        return cd.DeploymentsApi(horton.cad).create(
            environment=env_name,
            deployment_template=cd.DeploymentTemplate(
                name=dep_name,
                manager_virtual_instance=cd.VirtualInstance(
                    id=str(uuid.uuid4()),
                    template=template
                ),
                password=security.get_secret('ADMINPASSWORD'),
                enable_enterprise_trial=True,
                repository_key_url=repo_key,
                repository=repo,
                tls_enabled=tls_start,
                csds=csds,
                java_installation_strategy='NONE'
            )
        )
    except ApiException as e:
        if e.status == 409:
            log.warning('A deployment with the same name already exists')
        else:
            raise e


def delete_deployment(dep_name, env_name=None):
    env_name = env_name if env_name else horton.cdcred.name
    try:
        return cd.DeploymentsApi(horton.cad).delete(
            environment=env_name,
            deployment=dep_name
        )
    except ApiException as e:
        raise e


def get_deployment(dep_name=None, env_name=None):
    env_name = env_name if env_name else horton.cdcred.name
    dep_name = dep_name if dep_name else horton.cdcred.name
    log.info("Attempting to get deployment %s", dep_name)
    try:
        return cd.DeploymentsApi(horton.cad).get_redacted(
            environment=env_name,
            deployment=dep_name
        )
    except ApiException as e:
        if e.status == 404:
            log.error("Deployment %s not found", dep_name)
            return []
        else:
            raise e


def get_deployment_status(dep_name=None, env_name=None):
    env_name = env_name if env_name else horton.cdcred.name
    dep_name = dep_name if dep_name else horton.cdcred.name
    #log.info("Fetching Deployment status for [%s]", dep_name)
    try:
        return cd.DeploymentsApi(horton.cad).get_status(
            environment=env_name,
            deployment=dep_name
        )
    except ApiException as e:
        if e.status == 404:
            log.error("Deployment %s not found", dep_name)
            return None
        else:
            raise e


def list_clusters(env_name=None, dep_name=None):
    # Using default if available
    env_name = env_name if env_name else horton.cdcred.name
    dep_name = dep_name if dep_name else horton.cdcred.name
    cd.ClustersApi(horton.cad).list(
        environment=env_name,
        deployment=dep_name
    )


def create_instance_template(tem_name, env_name=None, image_id=None, scripts=None,
                             vm_type=None, subnet_id=None, sec_id=None):
    # This assumes that Cloudbreak aor Director have been deployed
    platform = config.profile.get('platform')
    details = horton.cbd.extra
    env_name = env_name if env_name else horton.cdcred.name
    # Script installs JDK1.8 and force-sets Chronyd to work if present
    bootstraps = [
        cd.Script(
            content='#!/bin/sh'
                    '\nyum remove --assumeyes *openjdk*'
                    '\nrpm -ivh "https://whoville.s3.eu-west-2.amazonaws.com/v2/or-jdk-8-212.rpm"'
                    '\necho "server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4" >> /etc/chrony.conf'
                    '\nservice chronyd restart'
                    '\nexit 0'
        )
    ]
    if scripts is not None:
        for s in scripts:
            bootstraps.append(cd.Script(content=s))
    if platform['provider'] == 'GCE':
        log.info("*** setting up GCE instance template ***")
        # Director won't recognise the GCE image name as valid, have to use the URL
        # https://community.cloudera.com/t5/Cloudera-Altus-Director/Instance-Template-Image-URLs-for-Cloudera-Director-on-Azure/td-p/45445
        image_id = image_id if image_id else [
            x for x in infra.create_libcloud_session().list_images()
            if details['image'] in x.name
        ][0].extra['selfLink']
        vm_type = vm_type if vm_type else details['machineType'].split('/')[-1]
        params = {
                    'zone': horton.cbd.extra["zone"].name,
                    'instanceNamePrefix': horton.namespace
                }
    else:  # assume AWS
        log.info("*** setting up AWS instance template ***")
        image_id = image_id if image_id else details['image_id']
        vm_type = vm_type if vm_type else details['instance_type']
        subnet_id = subnet_id if subnet_id else details['subnet_id']
        sec_id = sec_id if sec_id else details['groups'][0]['group_id']
        params = {
                    'subnetId': subnet_id,
                    'securityGroupsIds': sec_id,
                    'instanceNamePrefix': horton.namespace
                }
    cd.InstanceTemplatesApi(horton.cad).create(
        environment=env_name,
        instance_template=cd.InstanceTemplate(
            name=tem_name,
            image=image_id,
            type=vm_type,
            config=params,
            tags=config.profile['tags'],
            bootstrap_scripts=bootstraps
        )
    )


def get_instance_template(env_name=None, tem_name=None):
    env_name = env_name if env_name else horton.cdcred.name
    tem_name = tem_name if tem_name else horton.cdcred.name
    try:
        return cd.InstanceTemplatesApi(horton.cad).get(
            environment=env_name,
            template=tem_name
        )
    except ApiException as e:
        if e.status == 404:
            return []  # not found
        else:
            raise e


def create_cluster(cdh_ver, workers=3, services=None, env_name=None,
                   dep_name=None, clus_name=None, parcels=None):
    env_name = env_name if env_name else horton.cdcred.name
    dep_name = dep_name if dep_name else env_name + '-' + cdh_ver.replace(
        '.', '-')
    services = services if services else ['HDFS', 'YARN']
    if cdh_ver[0] == '5':
        load_parcels = ['https://archive.cloudera.com/cdh5/parcels/' +
                        cdh_ver + '/']
    elif cdh_ver[0] == '6':
        load_parcels = ['https://archive.cloudera.com/cdh6/' + cdh_ver +
                   '/parcels/']
    else:
        raise ValueError("Only CDH versions 5 or 6 supported")
    if parcels:
        load_parcels += parcels
        if cdh_ver[0] == '6':
            # CDH6 already has Kafka
            load_parcels = [x for x in load_parcels if 'kafka' not in x]
    products = {
        'CDH': cdh_ver
    }
    if 'NIFI' in str(services):
        products['CFM'] = '1'
    if 'KAFKA' in str(services) and cdh_ver[0] == '5':
        products['KAFKA'] = '4'
    if 'SCHEMAREGISTRY' in str(services):
        products['SCHEMAREGISTRY'] = '0.7'
    services_configs = {}
    master_setups = {}
    master_configs = {}
    worker_setups = {}
    worker_configs = {}
    if 'HDFS' in services:
        master_setups['HDFS'] = ['NAMENODE', 'SECONDARYNAMENODE']
        worker_setups['HDFS'] = ['DATANODE']
    if 'YARN' in services:
        master_setups['YARN'] = ['RESOURCEMANAGER', 'JOBHISTORY']
        worker_setups['YARN'] = ['NODEMANAGER']
    if 'ZOOKEEPER' in services:
        master_setups['ZOOKEEPER'] = ['SERVER']
    if 'HBASE' in services:
        master_setups['HBASE'] = ['MASTER']
        worker_setups['HBASE'] = ['REGIONSERVER']
    if 'HIVE' in services:
        master_setups['HIVE'] = ['HIVESERVER2', 'HIVEMETASTORE']
    if 'HUE' in services:
        master_setups['HUE'] = ['HUE_SERVER']
    if 'KUDU' in services:
        master_setups['KUDU'] = ['KUDU_MASTER']
        worker_setups['KUDU'] = ['KUDU_TSERVER']
        master_configs['KUDU'] = {
            'KUDU_MASTER': {
                'fs_wal_dir': "/data0/kudu/masterwal",
                'fs_data_dirs': "/data1/kudu/master"
            }
        }
        worker_configs['KUDU'] = {
            'KUDU_TSERVER': {
                'fs_wal_dir': "/data0/kudu/tabletwal",
                'fs_data_dirs': "/data1/kudu/tablet"
            }
        }
    if 'IMPALA' in services:
        master_setups['IMPALA'] = ['CATALOGSERVER', 'STATESTORE']
        worker_setups['IMPALA'] = ['IMPALAD']
    if 'NIFI' in services:
        worker_setups['NIFI'] = ['NIFI_NODE']
    if 'NIFIREGISTRY' in services:
        master_setups['NIFIREGISTRY'] = ['NIFI_REGISTRY_SERVER']
    if 'NIFITOOLKITCA' in services:
        master_setups['NIFITOOLKITCA'] = ['NIFI_TOOLKIT_SERVER']
        services_configs['NIFITOOLKITCA'] = {
            'nifi.toolkit.tls.ca.server.token': security.get_secret('MASTERKEY')
        }
    if 'KAFKA' in services:
        worker_setups['KAFKA'] = ['KAFKA_BROKER']
    if 'SCHEMAREGISTRY' in services:
        master_setups['SCHEMAREGISTRY'] = ['SCHEMA_REGISTRY_SERVER']
    clus_name = clus_name if clus_name else \
        horton.cdcred.name + '-' + str(cdh_ver).replace('.', '-')
    # Handle virtual instance generation
    master_vi = [create_virtual_instance(
        tem_name='master',
        scripts=[
            '''sudo -i
            yum install mysql mariadb-server -y
            systemctl enable mariadb
            service mariadb start
            mysql --execute="CREATE DATABASE registry DEFAULT CHARACTER SET utf8"
            mysql --execute="CREATE USER 'registry'@'localhost' IDENTIFIED BY 'registry'"
            mysql --execute="GRANT ALL PRIVILEGES ON registry.* TO 'registry'@'localhost' identified by 'registry'"
            mysql --execute="GRANT ALL PRIVILEGES ON registry.* TO 'registry'@'localhost' WITH GRANT OPTION"
            mysql --execute="FLUSH PRIVILEGES"
            mysql --execute="COMMIT"'''
        ]
    )]
    worker_vi = [create_virtual_instance() for _ in range(0, workers)]
    try:
        cd.ClustersApi(horton.cad).create(
            environment=env_name,
            deployment=dep_name,
            cluster_template=cd.ClusterTemplate(
                name=clus_name,
                product_versions=products,
                parcel_repositories=load_parcels,
                services=services,
                services_configs=services_configs,
                virtual_instance_groups={
                    'masters': cd.VirtualInstanceGroup(
                        name='masters',
                        min_count=1,
                        service_type_to_role_types=master_setups,
                        role_types_configs=master_configs,
                        virtual_instances=master_vi
                    ),
                    'workers': cd.VirtualInstanceGroup(
                        name='workers',
                        min_count=workers,
                        service_type_to_role_types=worker_setups,
                        role_types_configs=worker_configs,
                        virtual_instances=worker_vi
                    )
                }
            )
        )
    except ApiException as e:
        if e.status == 409:
            log.error("Cluster %s already exists", clus_name)
            raise ValueError("Cluster %s already exists", clus_name)
        else:
            raise e


def get_cluster(clus_name, dep_name=None, env_name=None):
    env_name = env_name if env_name else horton.cdcred.name
    dep_name = dep_name if dep_name else clus_name
    log.info("Attempting to get Cluster %s", clus_name)
    try:
        return cd.ClustersApi(horton.cad).get_redacted(
            environment=env_name,
            deployment=dep_name,
            cluster=clus_name
        )
    except ApiException as e:
        if e.status == 404:
            log.error("Cluster %s not found", dep_name)
            return []
        else:
            raise e


def get_cluster_status(clus_name, dep_name=None, env_name=None):
    env_name = env_name if env_name else horton.cdcred.name
    dep_name = dep_name if dep_name else clus_name
    #log.info("Fetching Cluster status for [%s]", clus_name)
    try:
        return cd.ClustersApi(horton.cad).get_status(
            environment=env_name,
            deployment=dep_name,
            cluster=clus_name
        )
    except ApiException as e:
        if e.status == 404:
            log.error("Cluster %s not found", dep_name)
            return None
        else:
            raise e


def create_virtual_instance(tem_name=None, scripts=None):
    tem_name = tem_name if tem_name else horton.cdcred.name
    template = get_instance_template(tem_name=tem_name)
    if not template:
        create_instance_template(tem_name, scripts=scripts)
        while not template:
            sleep(2)
            template = get_instance_template(tem_name=tem_name)
    return cd.VirtualInstance(
        id=str(uuid.uuid4()),
        template=template
    )


def chain_deploy(cdh_ver, dep_name=None, services=None, env_name=None,
                 clus_name=None, tls_start=False, csds=None, parcels=None):
    env_name = env_name if env_name else horton.cdcred.name
    assert isinstance(cdh_ver, six.string_types)
    assert services is None or isinstance(services, list)
    dep_name = dep_name if dep_name else env_name + '-' + cdh_ver.replace(
        '.', '-')
    clus_name = clus_name if clus_name else dep_name

    cm = get_deployment(dep_name=dep_name)
    if not cm:
        create_deployment(
            cm_ver=cdh_ver,
            dep_name=dep_name,
            tls_start=tls_start,
            csds=csds
        )
        sleep(3)
        cm_status = get_deployment_status(dep_name)
        log.info("Deploying Cloudera Manager %s", cdh_ver)
        while cm_status is None or \
                cm_status.stage not in ['READY', 'BOOTSTRAP_FAILED']:
            sleep(15)
            cm_status = get_deployment_status(dep_name)
            log.info("CM [%s] status: %s, Step %s/%s, %s",cdh_ver, cm_status.stage, cm_status.completed_steps,
                     cm_status.completed_steps + cm_status.remaining_steps, cm_status.description)
        cm = get_deployment(dep_name=dep_name)
    log.info("Cloudera Manager [%s] is available at http://%s:7180",
             cdh_ver, cm.manager_instance.properties['publicIpAddress'])
    cluster = get_cluster(clus_name=clus_name, dep_name=dep_name)
    if not cluster:
        log.info("Cluster not found, creating...")
        create_cluster(cdh_ver=cdh_ver, services=services, clus_name=clus_name,
                       dep_name=dep_name, parcels=parcels)
        clus_status = get_cluster_status(
            clus_name=clus_name, dep_name=dep_name
        )
        while clus_status is None or \
                clus_status.stage not in ['READY', 'BOOTSTRAP_FAILED']:
            log.info("Waiting 30s for Cluster [%s] to Deploy", cdh_ver)
            sleep(30)
            clus_status = get_cluster_status(
                clus_name=clus_name, dep_name=dep_name
            )
            log.info("Cluster [%s] status: %s, Step %s/%s, %s", dep_name, clus_status.stage, clus_status.completed_steps,
                     clus_status.completed_steps + clus_status.remaining_steps, clus_status.description)
    log.info("Cluster %s is deployed for %s", dep_name, cdh_ver)
    log.info("Cloudera Manager [%s] is available at http://%s:7180",
             cdh_ver, cm.manager_instance.properties['publicIpAddress'])
