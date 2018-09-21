# -*- coding: utf-8 -*-

"""
For interactions with Cloudbreak

Warnings:
    Experimental, not extensively tested
"""

from __future__ import absolute_import
import logging
import base64
import re
from datetime import datetime, timedelta
from calendar import timegm
import json
import six
import whoville
from whoville.cloudbreak.rest import ApiException
from whoville import utils

__all__ = [
    "list_credentials", 'create_credential', 'list_blueprints', 'list_recipes',
    'create_blueprint', 'delete_blueprint', 'get_blueprint', 'create_recipe',
    'delete_recipe', 'list_image_catalogs', 'create_image_catalog',
    'delete_image_catalog', 'get_images', 'get_regions_by_credential',
    'get_custom_params', 'get_credential', 'get_blueprint', 'get_images',
    'list_mpacks', 'create_mpack', 'delete_mpack', 'list_stacks',
    'get_stack_matrix', 'get_default_security_rules', 'get_ssh_keys',
    'prep_cluster', 'prep_dependencies', 'purge_cloudbreak',
    'prep_images_dependency', 'prep_stack_specs', 'purge_resource',
    'prep_instance_groups', 'create_stack', 'delete_stack',
    'delete_credential', 'get_events', 'monitor_event_stream',
    'create_auth_conf', 'delete_auth_conf', 'list_auth_confs'
]

log = logging.getLogger(__name__)

# Supported Resource Source locations in this code
valid_source_types = ['url', 'file']
# Separator char when parsing readable nested dict keys in this code
sep = ':'


@utils.singleton
class Horton:
    """
    Borg Singleton to share state between the various processes.
    Looks complicated, but it makes the rest of the code more readable for
    Non-Python natives.
    ...
    Why Horton? Because an Elephant Never Forgets
    """
    def __init__(self):
        self.cbd = None
        self.cred = None  # Credential for deployments, once loaded in CB
        self.resources = {}  # all loaded resources from github/files
        self.defs = {}  # deployment definitions, once pulled from resources
        self.specs = {}  # stack specifications, once formulated
        self.stacks = {}  # stacks deployed, once submitted
        self.deps = {}  # Dependencies loaded for a given Definition
        self.seq = {}  # Prioritised list of tasks to execute
        self.cache = {}  # Key:Value store for passing params between Defs
        self.namespace = whoville.config.profile['deploy']['namespace']
        self.global_purge = whoville.config.profile['deploy']['globalpurge']

    def find(self, items):
        """
        Convenience function to retrieve params in a very readable method

        Args:
            items (str): dot notation string of the key for the value to be
                retrieved. e.g 'secret.cloudbreak.hostnme'

        Returns:
            The value if found, or None if not
        """
        return whoville.utils.get_val(self, items, sep)


def list_credentials(**kwargs):
    return whoville.cloudbreak.V1credentialsApi().get_publics_credential(
        **kwargs
    )


def create_credential(from_profile=False, platform='AWS', desc='', name=None,
                      params=None, **kwargs):
    if from_profile:
        if platform == 'AWS':
            provider = 'EC2'
            infra = whoville.config.profile['infra'][provider]
            if 'credarn' in infra:
                sub_params = {
                    'roleArn': infra['credarn'],
                    'selector': 'role-based'
                }
            elif 'key' in infra:
                sub_params = {
                    'accessKey': infra['key'],
                    'secretKey': infra['secret'],
                    'selector': 'key-based'
                }
            else:
                raise ValueError("Could not determine Credential Type")
        else:
            raise ValueError("Platform [%s] unsupported", platform)
    else:
        if platform == 'EC2':
            selector = params['selector']
            if selector == 'role-based':
                sub_params = {x:y for x,y in params.items()
                              if x in ['selector', 'roleArn']}
            elif selector == 'key-based':
                sub_params = {x: y for x, y in params.items()
                              if x in ['selector', 'secretKey', 'accessKey']}
            else:
                raise ValueError("selector [%s] unrecognised for platform [%s]",
                                 selector, platform)
        else:
            raise ValueError("Platform [%s] unsupported", platform)
    return whoville.cloudbreak.V1credentialsApi().post_private_credential(
        body=whoville.cloudbreak.CredentialRequest(
            cloud_platform=platform,
            description=name,
            name=name,
            parameters=sub_params
        ),
        **kwargs
    )


def get_credential(name, create=False, purge=False, **kwargs):
    cred = [x for x in list_credentials() if name in x.name]
    if cred:
        log.info("Found existing Credential [%s]", name)
        if purge is True:
            log.info("Credential Purge set, removing [%s]", name)
            delete_credential(cred[0])
        else:
           return cred[0]
    if not create:
        log.info("Credential [%s] not found, Create not set, returning None",
                 name)
        return None
    log.info("Credential [%s] not found, Create set, Creating Credential",
             name)
    return create_credential(from_profile=True, name=name)


def delete_credential(identifier, identifier_type='id', **kwargs):
    return whoville.cloudbreak.V1credentialsApi().delete_credential(
        id=identifier
    )


def list_blueprints(bool_response=False, **kwargs):
    # Using this function as a test for the Cloudbreak Api being available
    try:
        bps = whoville.cloudbreak.V1blueprintsApi().get_publics_blueprint(
            **kwargs
        )
        return bps
    except ApiException as e:
        if bool_response:
            return False
        else:
            raise e


def create_blueprint(name, desc, blueprint, tags=None, **kwargs):
    log.info("Creating Blueprint [%s] with desc [%s] with Tags [%s]",
             name, desc, str(tags))
    return whoville.cloudbreak.V1blueprintsApi().post_private_blueprint(
        body=whoville.cloudbreak.BlueprintRequest(
            description=desc,
            name=name,
            ambari_blueprint=base64.b64encode(
                json.dumps(blueprint).encode()
            ).decode(),
            tags=tags
        )
    )


def delete_blueprint(bp_id, **kwargs):
    try:
        return whoville.cloudbreak.V1blueprintsApi().delete_blueprint(
            id=bp_id,
            **kwargs
        )
    except ApiException as e:
        raise e


def get_blueprint(identifier, identifier_type='name', **kwargs):
    if identifier_type == 'name':
        bp_info = whoville.cloudbreak.V1blueprintsApi().get_public_blueprint(
            name=identifier,
            **kwargs
        )
        bp_content = utils.load(bp_info.ambari_blueprint, decode='base64')
        return bp_info, bp_content
    else:
        raise ValueError("bad identifier type")


def create_recipe(name, desc, recipe_type, recipe, purge=False, **kwargs):
    log.info("Creating recipe [%s] with description [%s] of type [%s] with "
             "recipe like [%s] and purge:[%s]",
             name, desc, recipe_type, json.dumps(recipe)[:50], purge)
    if purge:
        target = [x.id for x in list_recipes() if x.name == name]
        if target:
            delete_recipe(target[0])
    return whoville.cloudbreak.V1recipesApi().post_private_recipe(
        # blueprint has to be a base64 encoded string for file upload
        body=whoville.cloudbreak.RecipeRequest(
            name=name,
            description=desc,
            recipe_type=recipe_type.upper(),
            content=(
                base64.b64encode(
                    bytes(recipe, 'utf-8')
                )
            ).decode('utf-8')
        ),
        **kwargs
    )


def list_recipes(**kwargs):
    return whoville.cloudbreak.V1recipesApi().get_publics_recipe(**kwargs)


def delete_recipe(rp_id, **kwargs):
    try:
        return whoville.cloudbreak.V1recipesApi().delete_recipe(
            id=rp_id,
            **kwargs
        )
    except ApiException as e:
        raise e


def list_image_catalogs(**kwargs):
    return whoville.cloudbreak.V1imagecatalogsApi().get_publics_image_catalogs(
        **kwargs
    )


def create_image_catalog(name, url, **kwargs):
    log.info("Creating Image Catalog [%s] at url [%s]",
             name, url)
    return whoville.cloudbreak.V1imagecatalogsApi().post_private_image_catalog(
        body=whoville.cloudbreak.ImageCatalogRequest(
            name=name,
            url=url,
        ),
        **kwargs
    )


def delete_image_catalog(name, **kwargs):
    assert isinstance(name, six.string_types)
    api = whoville.cloudbreak.V1imagecatalogsApi()
    return api.delete_public_image_catalog_by_name(
        name=name,
        **kwargs
    )


def get_images(platform, catalog=None, **kwargs):
    if catalog:
        return whoville.cloudbreak.V1imagecatalogsApi()\
            .get_public_images_by_provider_and_custom_image_catalog(
            name=catalog,
            platform=platform,
            **kwargs
        )
    return whoville.cloudbreak.V1imagecatalogsApi() \
        .get_images_by_provider(
        platform=platform,
        **kwargs
    )


def get_regions_by_credential(cred_name, **kwargs):
    return whoville.cloudbreak.V2connectorsApi().get_regions_by_credential_id(
        body=whoville.cloudbreak.PlatformResourceRequestJson(
            credential_name=cred_name,
            **kwargs
        )
    )


def get_custom_params(bp_name, **kwargs):
    return whoville.cloudbreak.V1utilApi().get_custom_parameters(
        body=whoville.cloudbreak.ParametersQueryRequest(
            blueprint_name=bp_name,
        ),
        **kwargs
    )


def list_stacks(**kwargs):
    return whoville.cloudbreak.V2stacksApi().get_publics_stack_v2(**kwargs)


def get_stack_matrix(**kwargs):
    return whoville.cloudbreak.V1utilApi().get_stack_matrix_util(**kwargs)


def get_default_security_rules(**kwargs):
    return whoville.cloudbreak.V1securityrulesApi().get_default_security_rules(
        **kwargs
    )


def get_ssh_keys(params, **kwargs):
    body = whoville.cloudbreak.RecommendationRequestJson()
    _ = {body.__setattr__(x, y) for x, y in params.items()}
    return whoville.cloudbreak.V1connectorsApi().get_platform_s_sh_keys(
        body=body,
        **kwargs
    )


def list_mpacks(**kwargs):
    return whoville.cloudbreak.V1mpacksApi().get_public_management_packs(
        **kwargs
    )


def create_mpack(name, desc, url, purge_on_install, **kwargs):
    log.info("Creating MPack [%s] with desc [%s] from url [%s] with "
             "purge_on_install as [%s]",
             name, desc, url[:50], purge_on_install)
    return whoville.cloudbreak.V1mpacksApi().post_public_management_pack(
        body=whoville.cloudbreak.ManagementPackRequest(
            name=name,
            description=desc,
            mpack_url=url,
            purge=purge_on_install
        ),
        **kwargs
    )


def delete_mpack(name, **kwargs):
    assert isinstance(name, six.string_types)
    return whoville.cloudbreak.V1mpacksApi().delete_public_management_pack(
        name=name,
        **kwargs
    )


def prep_dependencies(def_key, shortname=None):
    log.info("---- Preparing Dependencies for Definition [%s] with Name "
             "override [%s]", def_key, shortname)
    horton = Horton()
    supported_resouces = ['recipe', 'blueprint', 'catalog', 'mpack', 'auth']
    current = {
        'blueprint': list_blueprints(),
        'recipe': list_recipes(),
        'catalog': list_image_catalogs(),
        'mpack': list_mpacks(),
        'auth': list_auth_confs()
    }

    if horton.global_purge:
        purge = True
    elif 'purge' in horton.defs[def_key]['control']:
        purge = horton.defs[def_key]['control']['purge']
    else:
        purge = False

    fullname = horton.namespace + shortname if shortname else horton.namespace + def_key
    deps = {}
    log.debug("Def like [%s]", json.dumps(horton.defs[def_key]))
    for res_type in [x for x in horton.defs[def_key].keys() if x in supported_resouces]:
        log.debug("res_type like [%s]", res_type)
        res_defs = horton.defs[def_key][res_type]
        if not isinstance(res_defs, list):
            res_defs = [res_defs]
        for res in res_defs:
            log.debug("resource like [%s]", json.dumps(res))
            dep = None
            if not res:
                # resource in def, but not populated
                log.info("Resource for res_type [%s] not in demo [%s], "
                         "skipping...", res_type, horton.defs[def_key]['name'])
                break
            log.info("checking Resource type [%s]", res_type)
            if 'name' in res and res['name']:
                res_name = '-'.join([fullname, res['name']])
                res_name = res_name.rsplit('.')[0]
                log.info("Resource has default Name [%s], using ResName [%s]",
                         res['name'], res_name)
            else:
                # res has name field but not populated
                log.info("Resource name field present but empty, "
                         "skipping...")
                break
            if not purge:
                # if not purging resource, check it's not already loaded
                dep = [x for x in current[res_type] if res_name == x.name]
                if dep:
                    log.info("Resource [%s]:[%s] already loaded and Purge "
                             "not set, skipping...",
                             res_type, res_name)
            else:
                purge_resource(res_name, res_type)
            desc = res['desc'] if 'desc' in res else ''
            if res_type not in deps and res_type in ['recipe', 'mpack', 'auth']:
                # Treat everything as a list for simplicity
                deps[res_type] = []
            if res_type == 'blueprint':
                if dep:
                    deps[res_type] = dep[0]
                else:
                    deps[res_type] = \
                        whoville.deploy.create_blueprint(
                            source='file',
                            desc=desc,
                            name=res_name,
                            blueprint=horton.resources[def_key][res['name']]
                        )
            if res_type == 'catalog':
                if dep:
                    deps[res_type] = dep[0]
                else:
                    deps[res_type] = \
                        whoville.deploy.create_image_catalog(
                        name=res_name,
                        url=horton.defs[def_key][res_type]['def']
                    )

            if res_type == 'recipe':
                if dep:
                    deps[res_type].append(dep[0])
                else:
                    deps[res_type].append(
                        whoville.deploy.create_recipe(
                            name=res_name,
                            desc=desc,
                            recipe_type=res['typ'],
                            recipe=horton.resources[def_key][res['name']]
                        )
                    )
            if res_type == 'mpack':
                if dep:
                    deps[res_type].append(dep[0])
                else:
                    if 'purge_on_install' in res:
                        purge_on_install = res['purge_on_install']
                    else:
                        purge_on_install = False
                    deps[res_type].append(
                        create_mpack(
                            name=res_name,
                            desc=desc,
                            url=res['url'],
                            purge_on_install=purge_on_install
                        )
                    )
            if res_type == 'auth':
                if dep:
                    deps[res_type].append(dep[0])
                else:
                    if 'params' in res:
                        params = res['params']
                    else:
                        params = None
                    deps[res_type].append(
                        whoville.deploy.create_auth_conf(
                            name=res_name,
                            host=res['host'],
                            params=params
                        )
                    )
    horton.deps[fullname] = deps
    prep_images_dependency(def_key, fullname)
    horton.deps[fullname]['gateway'] = find_ambari_group(def_key, fullname)


def find_ambari_group(def_key, name=None):
    horton = Horton()
    name = horton.namespace + name if name else horton.namespace + def_key
    # If only one group, it must be the gateway
    if 'group' in horton.defs[def_key]:
        if len(horton.defs[def_key]['group']) == 1:
            return horton.defs[def_key]['group'][0]['name']
        else:
            test =[x['name'] for x in horton.defs[def_key]['group'] if x['type'] == 'GATEWAY']
            if test:
                # If the demo has a gateway defined, use it
                return test[0]
            else:
                # Else raise an error for bad group config
                raise ValueError("No GATEWAY specified in Group config")
    else:
        # Try finding it in the Blueprint
        bp_content = utils.load(
            horton.deps[name]['blueprint'].ambari_blueprint,
            decode='base64'
        )
        for host_group in bp_content['host_groups']:
            for component in host_group['components']:
                if component['name'] == 'AMBARI_SERVER':
                    return host_group['name']
    raise ValueError("Couldn't find Gateway or Ambari Server in definitions")


def prep_images_dependency(def_key, fullname=None):
    horton = Horton()
    log.info("Prepping valid images for demo spec")
    cat_name = horton.find('defs:' + def_key + ':catalog')
    tgt_os = horton.find('defs:' + def_key + ':infra:os')
    bp_content = utils.load(
        horton.deps[fullname]['blueprint'].ambari_blueprint, decode='base64'
    )
    stack_name = bp_content['Blueprints']['stack_name']
    stack_version = bp_content['Blueprints']['stack_version']
    log.info("fetching stack matrix for name:version [%s]:[%s]",
             stack_name, stack_version)
    stack_matrix = whoville.deploy.get_stack_matrix()
    stack_root = whoville.utils.get_val(
        stack_matrix,
        [stack_name.lower(),
         bp_content['Blueprints']['stack_version']]
    )
    images = whoville.deploy.get_images(
        catalog=cat_name,
        platform=horton.cred.cloud_platform
    )
    log.info("Fetched images from Cloudbreak [%s]", str(images.attribute_map)[:100])

    images_by_type = [
        x for x in
        images.base_images + images.__getattribute__(stack_name.lower() + '_images')
    ]
    if tgt_os:
        images_by_os = [x for x in images_by_type if x.os == tgt_os]
    else:
        images_by_os = images_by_type
    log.info("Filtered images by OS [%s] and found [%d]", tgt_os,
             len(images_by_os))
    valid_images = []
    for image in images_by_os:
        if type(image) == whoville.cloudbreak.BaseImageResponse:
            ver_check = [
                x.version for x in image.__getattribute__(
                    '_'.join([stack_name.lower(), 'stacks'])
                ) if x.version == stack_root.version
            ]
            if ver_check:
                valid_images.append(image)
        elif type(image) == whoville.cloudbreak.ImageResponse:
            if image.stack_details.version == stack_root.version:
                valid_images.append(image)

    if valid_images:
        log.info("found [%d] images matching requirements", len(valid_images))
        prewarmed = [
            x for x in valid_images
            if isinstance(x, whoville.cloudbreak.ImageResponse)
        ]
        if prewarmed:
            valid_images = prewarmed
        horton.deps[fullname]['images'] = valid_images
    else:
        raise ValueError("No Valid Images found for stack definition")


def prep_cluster(def_key, fullname=None):
    horton = Horton()
    log.info("prepping stack cluster settings")
    tgt_os_name = horton.deps[fullname]['images'][0].os
    mpacks = [{'name': '-'.join([fullname, x['name']])}
              for x in horton.defs[def_key]['mpack']
              ] if 'mpack' in horton.defs[def_key] else []
    bp_content = utils.load(
        horton.deps[fullname]['blueprint'].ambari_blueprint, decode='base64'
    )
    stack_name = bp_content['Blueprints']['stack_name']
    stack_version = bp_content['Blueprints']['stack_version']

    # Cloud Storage
    object_store = whoville.config.profile['deploy']['objectstore']
    if object_store:
        if 'cloudstor' in horton.defs[def_key]['infra']:
            if object_store == 's3':
                bucket = whoville.config.profile['deploy']['bucket']
                cloud_stor = whoville.cloudbreak.CloudStorageRequest(
                    s3=whoville.cloudbreak.S3CloudStorageParameters(
                        instance_profile=whoville.config.profile['deploy']['bucketrole']
                    ),
                    locations=[]
                )
                for loc in horton.defs[def_key]['infra']['cloudstor']:
                    cloud_stor.locations.append({
                        "value": "s3a://" + bucket + loc['value'],
                        "propertyFile": loc['propfile'],
                        "propertyName": loc['propname']
                    })
            else:
                raise ValueError("Object Store [%s] not supported", object_store)
        else:
            log.info("cloudstorage not defined in demo, skipping...")
            cloud_stor = None
    else:
        cloud_stor = None

    log.info("using mpack [%s]", str(mpacks))

    cluster_req = whoville.cloudbreak.ClusterV2Request(
                ambari=whoville.cloudbreak.AmbariV2Request(
                    blueprint_name=horton.deps[fullname]['blueprint'].name,
                    ambari_stack_details=whoville.cloudbreak.AmbariStackDetails(
                        version=stack_version,
                        verify=False,
                        enable_gpl_repo=False,
                        stack=stack_name,
                        os=tgt_os_name,
                        mpacks=mpacks
                    ),
                    user_name=whoville.config.profile['deploy']['username'],
                    password=whoville.config.profile['deploy']['password'],
                    validate_blueprint=False,  # Hardcoded?
                    ambari_security_master_key=whoville.config.profile['deploy']['password'],
                    kerberos=None,
                    enable_security=False  # Hardcoded?
                ),
                cloud_storage=cloud_stor
            )
    # TODO: Replace MasterKey with Random function
    if 'auth' in horton.defs[def_key] and 'name' in horton.defs[def_key]['auth']:
        cluster_req.ldap_config_name = '-'.join([fullname, horton.defs[def_key]['auth']['name']])
        cluster_req.proxy_name = None
    if 'proxy' in horton.defs[def_key] and horton.defs[def_key]['proxy']:
        cluster_req.ambari.gateway = whoville.cloudbreak.GatewayJson(
            enable_gateway=True,
            sso_type=horton.defs[def_key]['proxy']['sso'],
            topologies=[
                whoville.cloudbreak.GatewayTopologyJson(
                    topology_name='dp-proxy',
                    exposed_services=horton.defs[def_key]['proxy']['services']
                )
            ]
        )
    if 'stackrepo' in horton.defs[def_key]['infra']:
        cluster_req.ambari.ambari_stack_details.repository_version = horton.defs[def_key]['infra']['stackrepo']['ver']
        cluster_req.ambari.ambari_stack_details.version_definition_file_url = horton.defs[def_key]['infra']['stackrepo']['url']
    if 'ambarirepo' in horton.defs[def_key]['infra']:
        ambari_repo = {
            x: y for x, y in horton.defs[def_key]['infra']['ambarirepo'].items()
        }
        cluster_req.ambari.ambari_repo_details_json = ambari_repo
    if 'krb' in horton.defs[def_key]:
        if horton.defs[def_key]['krb'] and 'mode' in horton.defs[def_key]['krb']:
            if not horton.defs[def_key]['krb']['mode'] == 'test':
                raise ValueError("Kerberising in Cloudbreak Test Mode Only")
            cluster_req.ambari.enable_security = True
            cluster_req.ambari.kerberos = whoville.cloudbreak.KerberosRequest(
                admin=horton.find('secret:clustercred:username'),
                password=horton.find('secret:clustercred:password'),
                master_key=horton.find('secret:clustercred:masterkey'),
                tcp_allowed=False
            )
    return cluster_req


def prep_instance_groups(def_key, fullname):
    horton = Horton()
    log.info("Prepping instance groups")
    region = horton.specs[fullname].placement.region
    avzone = horton.specs[fullname].placement.availability_zone
    log.info("Fetching Infrastructure recommendation for "
             "credential[%s]:blueprint[%s]:region[%s]:availability zone[%s]",
             horton.cred.name, horton.deps[fullname]['blueprint'].name,
             region, avzone)

    recs = whoville.cloudbreak.V1connectorsApi().create_recommendation(
        body=whoville.cloudbreak.RecommendationRequestJson(
            availability_zone=avzone,
            region=region,
            blueprint_id=horton.deps[fullname]['blueprint'].id,
            credential_id=horton.cred.id
        )
    )
    log.info("Handling Security Rules")
    sec_group = horton.cbd.extra['groups'][0]['group_id']
    if sec_group:
        # Predefined Security Group
        sec_group = whoville.cloudbreak.SecurityGroupResponse(
            security_group_id=sec_group,
            cloud_platform=horton.cred.cloud_platform
        )
    else:
        raise ValueError("Network Security Group not Provided")
    groups = []
    log.info("found recommendations for instance groups [%s]",
             str(recs.recommendations.keys()))
    for group in recs.recommendations.keys():
        log.info("handling group [%s]", group)
        rec = recs.recommendations[group]
        group_def = [x for x in horton.defs[def_key]['group'] if x['name'] == group]
        if group_def:
            group_def = group_def[0]
            log.info("Group [%s] found in demo def, proceeding...",
                     group)
        else:
            log.info("Group [%s] not in demo def, using defaults...", group)
            group_def = {}
        nodes = group_def['nodes'] if 'nodes' in group_def else 1
        machine = group_def['machine'] if 'machine' in group_def else None
        if 'recipe' in group_def and group_def['recipe'] is not None:
            recipes = ['-'.join([fullname, x]) for x in group_def['recipe']]
        else:
            recipes = []
        log.info("Using Recipe list [%s]", str(recipes))
        if horton.deps[fullname]['gateway'] == group:
            # This is the Ambari group
            typ = 'GATEWAY'
        else:
            typ = 'CORE'
        disk_types = [x.name for x in recs.disk_responses]
        vol_type = sorted([
            x for x in disk_types
            if x in horton.defs[def_key]['infra']['disktypes']])[0]
        log.info("selected disk type [%s] from preferred list [%s] out of "
                 "available types [%s]",
                 vol_type, str(horton.defs[def_key]['infra']['disktypes']),
                 str(disk_types))
        root_vol_size = rec.vm_type_meta_json.properties[
                            'recommendedRootVolumeSize']
        log.info("using root vol size [%s]", root_vol_size)
        vol_count = rec.vm_type_meta_json.properties[
                            'recommendedvolumeCount']
        vol_size = rec.vm_type_meta_json.properties[
                            'recommendedvolumeSizeGB']
        log.info("using [%s] volumes of size [%s]", vol_count, vol_size)
        item = whoville.cloudbreak.InstanceGroupsV2(
                    security_group=sec_group,
                    template=whoville.cloudbreak.TemplateV2Request(
                        parameters={
                            'encrypted': False  # Hardcoded?
                        },
                        instance_type=machine if machine else rec.value,
                        volume_count=vol_count,
                        volume_size=vol_size,
                        root_volume_size=root_vol_size,
                        volume_type=vol_type
                    ),
                    node_count=nodes,
                    group=group,
                    type=typ,
                    recovery_mode='MANUAL',  # Hardcoded?
                    recipe_names=recipes
            )
        groups.append(item)
    log.info("Finished Prepping Groups")
    return groups


def prep_stack_specs(def_key, name=None):
    horton = Horton()
    fullname = horton.namespace + name if name else horton.namespace + def_key
    log.info("Preparing Spec for Def [%s] as Name [%s]", def_key, fullname)
    cat_name = horton.find('defs:' + def_key + ':catalog')
    if horton.global_purge or horton.defs[def_key]['control']['purge']:
        stack = [x for x in list_stacks() if x.name == fullname]
        if stack:
            delete_stack(stack[0].id)
    # Sequence matters here, as some later params are have deps in earlier
    # Which also means you can't be clever and define it in one big call
    # Making Placeholder
    horton.specs[fullname] = whoville.cloudbreak.StackV2Request(
        general='', instance_groups=''
    )
    horton.specs[fullname].tags = {
        'Owner': horton.cred.name,
        'EndDate': (
            datetime.now() + timedelta(days=2)).strftime("%d%b%Y"),
        'StartDate': datetime.now().strftime("%d%b%Y")
    }
    horton.specs[fullname].stack_authentication = \
        whoville.cloudbreak.StackAuthenticationResponse(
                public_key_id=whoville.config.profile['deploy']['sshkey_name']
            )
    horton.specs[fullname].general = whoville.cloudbreak.GeneralSettings(
            credential_name=horton.cred.name,
            name=fullname
        )
    horton.specs[fullname].image_settings = \
        whoville.cloudbreak.ImageSettings(
            image_catalog=cat_name,
            image_id=horton.deps[fullname]['images'][0].uuid
        )
    horton.specs[fullname].placement = whoville.cloudbreak.PlacementSettings(
            region=horton.cbd.extra['availability'][:-1],
            availability_zone=horton.cbd.extra['availability']
        )
    horton.specs[fullname].network = whoville.cloudbreak.NetworkV2Request(
        parameters={
            'subnetId': horton.cbd.extra['subnet_id'],
            'vpcId': horton.cbd.extra['vpc_id']
        }
    )
    horton.specs[fullname].cluster = prep_cluster(def_key, fullname)
    if 'input' in horton.defs[def_key]:
        horton.specs[fullname].inputs = horton.defs[def_key]['input']
    horton.specs[fullname].instance_groups = prep_instance_groups(def_key, fullname)


def create_stack(name, wait=False, purge=False, **kwargs):
    log.info("Running Create Stack [%s] with wait [%s] and purge [%s]",
             name, wait, purge)
    horton = Horton()
    start_ts = datetime.utcnow()
    stack = [x for x in list_stacks() if x.name == name]
    if stack:
        if horton.global_purge or purge:
            log.info("Stack [%s] Exists and Purge is True, deleting",
                     name)
            delete_stack(stack[0].id)
        else:
            log.info("Stack [%s] Exists and Purge is False, returning Existing"
                     "Stack", name)
            return stack[0]
    log.info("Stack [%s] not found, Creating", name)
    resp = whoville.cloudbreak.V2stacksApi().post_private_stack_v2(
        body=horton.specs[name],
        **kwargs
    )
    if wait:
        whoville.utils.wait_to_complete(
            monitor_event_stream,
            start_ts=start_ts,
            identity=('stack_id', resp.id),
            target_event=('stack_status', 'AVAILABLE'),
            valid_events=[
                'UPDATE_IN_PROGRESS', 'BILLING_STARTED', 'AVAILABLE',
                'CREATE_IN_PROGRESS'
            ],
            whoville_delay=15,
            whoville_max_wait=wait
        )
    return resp


def delete_stack(stack_id, force=False, wait=True, **kwargs):
    log.info("Requesting delete of Stack [%d] params Force [%s] and Wait "
             "[%s]", stack_id, force, wait)
    start_ts = datetime.utcnow()
    resp = whoville.cloudbreak.V2stacksApi().delete_stack_v2(
        id=stack_id,
        forced=force,
        **kwargs
    )
    if wait:
        whoville.utils.wait_to_complete(
            monitor_event_stream,
            start_ts=start_ts,
            identity=('stack_id', stack_id),
            target_event=('stack_status', 'DELETE_COMPLETED'),
            valid_events=['DELETE_IN_PROGRESS'],
            whoville_delay=20,
            whoville_max_wait=300
        )
    return resp


def monitor_event_stream(start_ts, identity, target_event, valid_events,
                         **kwargs):
    log.info("Monitoring event stream from [%s] for Event [%s] for Identity "
             "[%s] against Valid Events [%s]",
             str(start_ts), str(target_event), str(identity), str(valid_events))
    events = whoville.deploy.get_events(
        start_ts=start_ts,
        select_by=identity,
    )
    event_set = set([x.__getattribute__(target_event[0])
                     for x in events])
    log.info("Found event set [%s] for target event [%s]",
             str(event_set), target_event[0])
    if target_event[1] in event_set:
        return True
    valid_test = [x for x in event_set if x not in valid_events]
    if valid_test:
        raise ValueError("Found Event {0} for Identity {1} which is not in"
                         "Valid Event list {2}".format(
            str(valid_test), str(identity), str(valid_events)))
    return False


def get_events(start_ts=None, select_by=None, ordered_by='event_timestamp',
               raw_input=False, raw_output=False):
    # ts from Cloudbreak are natively in ms, which breaks some python calls
    if start_ts:
        # raw_input means pas the start_ts unhindered
        # otherwise it's treated as a python datetime object
        if raw_input:
            submit_ts = start_ts
        else:
            # standard pythong ts is in s, so x1000 for ms
            # as Cloudbreak seems to assume that all ts are in ms
            submit_ts = timegm(start_ts.timetuple()) * 1000
        events = whoville.cloudbreak.V1eventsApi().get_events(
            since=submit_ts)
    else:
        events = whoville.cloudbreak.V1eventsApi().get_events()
    # Handle filtering whole events by a particular (field, key) tuple
    if not select_by:
        selected = events
    else:
        selected = [
            x for x in events
            if x.__getattribute__(select_by[0]) == select_by[1]
        ]
    # convert ts to s in datetime if requested, should be this by default
    if not raw_output:
        for e in selected:
            _ = {e.__setattr__(
                k,
                datetime(1970, 1, 1) + timedelta(milliseconds=e.event_timestamp)
            )
             for k in e.swagger_types.keys()
             if k == 'event_timestamp'}
    # return list of events sorted by ordered_by, defaults to event time
    return sorted(selected, key=lambda k: k.__getattribute__(ordered_by))


def purge_resource(res_name, res_type):
    log.info("Requested to Purge Resource [%s] of Type [%s]",
             res_name, res_type)
    # check for compatibility
    res_types = ['recipe', 'mpack', 'stack', 'blueprint', 'credential',
                 'recipe', 'catalog', 'auth']
    if res_type in res_types:
        # Set the param to identify the target resource

        if res_type in ['catalog', 'mpack', 'auth']:
            del_arg = 'name'
        else:
            del_arg = 'id'
        # rename if necessary

        if res_type == 'catalog':
            res_type = 'image_catalog'
        if res_type == 'auth':
            res_type = 'auth_conf'

        # set extra kwargs for submission
        if res_type == 'stack':
            params = {
                'force': True,
                'wait': True
            }
        else:
            params = {}
    else:
        raise ValueError("res_type [%s] unsupported", res_type)
    # select functions
    target = [x for x in getattr(whoville.deploy, 'list_' + res_type + 's')()
              if x.name == res_name]
    if not target:
        log.info("Resource named [%s] of Type [%s] not found, skipping delete",
                 res_name, res_type)
        return
    try:
        log.info("Attempting Delete of [%s]:[%s] identified by [%s]",
                 res_type, res_name, del_arg)
        getattr(whoville.deploy, 'delete_' + res_type)(
            target[0].__getattribute__(del_arg),
            **params
        )
        log.info("Deleted [%s]:[%s] identified by [%s]",
                 res_type, res_name, del_arg)
    except ApiException as e:
        if 'Please remove this cluster' in e.body:
            log.info("Delete blocked by dependency, requesting Purge of "
                     "dependency")
            new_target = re.search('cluster \[\'(.*?)\'\]', e.body)
            purge_resource(
                res_type='stack',
                res_name=new_target.group(1)
            )
            # Try again, still recursively
            purge_resource(
                res_type=res_type,
                res_name=res_name
            )
        else:
            raise e
    # execute


def purge_cloudbreak(for_reals, namespace=''):
    if not for_reals:
        raise ValueError("Cowardly not purging Cloudbreak as you didn't say "
                         "for reals. Please check function definition")
    # Stacks first because of dependencies
    log.info("Purging stacks")
    [delete_stack(x.id, force=True)
     for x in list_stacks()
     if namespace in x.name]
    # Then other stuff
    # Images
    log.info("Purging Images")
    [delete_image_catalog(x.name)
     for x in list_image_catalogs()
     if x.used_as_default is False and namespace in x.name]
    # Blueprints
    log.info("Purging Blueprints")
    [delete_blueprint(x.id)
     for x in list_blueprints()
     if namespace in x.name]
    # Recipes
    log.info("Purging Recipes")
    [delete_recipe(x.id)
     for x in list_recipes()
     if namespace in x.name]
    # Credentials
    log.info("Purging Credentials")
    [delete_credential(x.id)
     for x in list_credentials()
     if namespace in x.name]
    # Mpacks
    log.info("Purging MPacks")
    [delete_mpack(x.name)
     for x in list_mpacks()
     if namespace in x.name]


def list_auth_confs():
    return whoville.cloudbreak.V1ldapApi().get_publics_ldap()


def delete_auth_conf(auth_name):
    return whoville.cloudbreak.V1ldapApi().delete_private_ldap(auth_name)


def create_auth_conf(name, host, params=None):
    horton = Horton()
    # TODO: UnHack the DPSPUBLICIP Hacky Hacksaw II: The Revenging
    obj = whoville.cloudbreak.LdapConfigRequest(
        name=name,
        server_host=host if host != 'DPSPUBLICIP' else horton.cache['DPSPUBLICIP'],
        server_port=33389,
        directory_type='LDAP',
        protocol='ldap',
        bind_dn='uid=admin,ou=people,dc=hadoop,dc=apache,dc=org',
        bind_password='admin-password1',
        user_search_base='ou=people,dc=hadoop,dc=apache,dc=org',
        user_dn_pattern='cn={0}',
        user_object_class='person',
        user_name_attribute='uid',
        group_search_base='ou=groups,dc=hadoop,dc=apache,dc=org',
        group_object_class='groupOfNames',
        group_member_attribute='member',
        group_name_attribute='member',
        domain='',
        admin_group=''
    )
    if params:
        for k, v in params.items():
            obj.__setattr__(k, v)
    return whoville.cloudbreak.V1ldapApi().post_private_ldap(
        body=obj
    )


def wait_for_event(name, state, start_ts, wait):
    log.info("Waiting against state [%s] for Stack [%s]",
             state, name)
    event_key = {
        'DELETE_IN_PROGRESS': 10,
        'DELETE_COMPLETED': 20,
        'BILLING_TERMINATED': 25,
        'REQUESTED': 30,
        'CREATE_IN_PROGRESS': 40,
        'BILLING_STARTED': 50,
        'UPDATE_IN_PROGRESS': 60,
        'AVAILABLE': 70,
    }
    target_level = event_key[state]
    stack = [x for x in list_stacks()
             if x.name == name]
    if stack:
        current_level = event_key[stack[0].status]
        if current_level >= target_level:
            log.info("Stack [%s] at State [%s], which is higher than [%s], "
                     "Returning Success", name, stack[0].status, state)
            return
    whoville.utils.wait_to_complete(
        monitor_event_stream,
        start_ts=start_ts,
        identity=('stack_name', name),
        target_event=('event_type', state),
        valid_events=[
            'UPDATE_IN_PROGRESS', 'BILLING_STARTED', 'AVAILABLE',
            'CREATE_IN_PROGRESS', 'DELETE_IN_PROGRESS', 'DELETE_COMPLETED',
            'BILLING_TERMINATED'
        ],
        whoville_delay=15,
        whoville_max_wait=wait
    )


def add_security_rule(cidr, start, end, protocol):
    horton = Horton()
    if horton.cred.cloud_platform == 'AWS':
        whoville.infra.add_sec_rule_to_ec2_group(
            session=whoville.infra.create_libcloud_session(),
            rule={
                'protocol': protocol,
                'from_port': start,
                'to_port': end,
                'cidr_ips': [cidr]
            },
            sec_group_id=horton.cbd.extra['groups'][0]['group_id']
        )
    else:
        raise ValueError("Cloud Platform not Supported")


def write_cache(name, item, cache_key):
    log.info("Writing [%s] from [%s] to Horton Cache key [%s]")
    horton = Horton()
    if item in ['public_ip']:
        stack = [x for x in list_stacks()
                 if x.name == name][0]
        group = [x for x in stack.instance_groups
                  if x.type == 'GATEWAY'][0]
        instance = [x for x in group.metadata
                    if x.ambari_server == True][0]
        horton.cache[cache_key] = instance.__getattribute__(item)


def replace_string_in_resource(name, target, cache_key):
    horton = Horton()
    horton.resources[name][target].replace(cache_key, horton.cache[cache_key])