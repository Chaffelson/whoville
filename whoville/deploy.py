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
import sys
from time import sleep
from datetime import datetime, timedelta
from calendar import timegm
import json
import six
from whoville import config, utils, infra, security
from whoville import cloudbreak as cb
from whoville.cloudbreak.rest import ApiException


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
    'create_auth_conf', 'delete_auth_conf', 'list_auth_confs', 'list_dependencies'
]

log = logging.getLogger(__name__)

# Supported Resource Source locations in this code
valid_source_types = ['url', 'file']
# Separator char when parsing readable nested dict keys in this code
sep = ':'

# All Stack statuses, taken from cloudbreak/models/StackResponse/status
# and cloudbreak/model/ClusterResponse/status
stack_resp = ["REQUESTED", "CREATE_IN_PROGRESS", "AVAILABLE",
              "UPDATE_IN_PROGRESS", "UPDATE_REQUESTED", "UPDATE_FAILED",
              "CREATE_FAILED", "ENABLE_SECURITY_FAILED",
              "PRE_DELETE_IN_PROGRESS", "DELETE_IN_PROGRESS", "DELETE_FAILED",
              "DELETE_COMPLETED", "STOPPED", "STOP_REQUESTED",
              "START_REQUESTED", "STOP_IN_PROGRESS", "START_IN_PROGRESS",
              "START_FAILED", "STOP_FAILED", "WAIT_FOR_SYNC"]

cluster_resp = ["REQUESTED", "CREATE_IN_PROGRESS", "AVAILABLE",
                "UPDATE_IN_PROGRESS", "UPDATE_REQUESTED", "UPDATE_FAILED",
                "CREATE_FAILED", "ENABLE_SECURITY_FAILED",
                "PRE_DELETE_IN_PROGRESS", "DELETE_IN_PROGRESS",
                "DELETE_FAILED", "DELETE_COMPLETED", "STOPPED",
                "STOP_REQUESTED", "START_REQUESTED", "STOP_IN_PROGRESS",
                "START_IN_PROGRESS", "START_FAILED", "STOP_FAILED",
                "WAIT_FOR_SYNC"]


def list_credentials(**kwargs):
    return cb.V1credentialsApi().get_publics_credential(
        **kwargs
    )


def create_credential(from_profile=False, platform='EC2', name=None,
                      params=None, **kwargs):
    if from_profile:
        platform = config.profile.get('platform')
        if platform['provider'] == 'OPENSTACK':
            service = platform['provider']
            sub_params = {
                "endpoint": platform['auth_url'] + "/v3",
                "facing": "internal",
                "keystoneAuthScope": "cb-keystone-v3-project-scope",
                "selector": "cb-keystone-v3-project-scope",
                "keystoneVersion": "cb-keystone-v3",
                "password": platform['password'],
                "userDomain": "Default",
                "userName": platform['username'],
                "projectDomainName": "Default",
                "projectName": platform['project'].upper()
            }
        elif platform['provider'] == 'EC2':
            service = 'AWS'
            if 'credarn' in platform:
                sub_params = {
                    'roleArn': platform['credarn'],
                    'selector': 'role-based'
                }
            elif 'key' in platform:
                sub_params = {
                    'accessKey': platform['key'],
                    'secretKey': platform['secret'],
                    'selector': 'key-based'
                }
            else:
                raise ValueError("Could not determine Credential Type")
        elif platform['provider'] == 'AZURE_ARM':
            service = 'AZURE'
            if 'application' in platform:
                sub_params = {
                    'subscriptionId': platform['subscription'],
                    'tenantId': platform['tenant'],
                    'accessKey': platform['application'],
                    'secretKey': platform['secret'],
                    'selector': 'app-based'
                }
            else:
                raise ValueError("Could not determine Credential Type")
        elif platform['provider'] == 'GCE':
            service = 'GCP'
            if 'apikeypath' in platform:
                apikey = open(platform['apikeypath'], "r")
                apikey_encoded = apikey.read().encode()
                apikey_encoded_base64 = base64.urlsafe_b64encode(
                    apikey_encoded)
                apikey_encoded_base64_str = str(
                    apikey_encoded_base64).replace("b'","").replace("'","")
                sub_params = {
                    'credentialJson': apikey_encoded_base64_str,
                    'selector': 'credential-json'
                }
            else:
                raise ValueError("Could not determine Credential Type")
        else:
            raise ValueError("Platform [%s] unsupported", platform)
    else:
        if platform == 'EC2':
            service = 'AWS'
            selector = params['selector']
            if selector == 'role-based':
                sub_params = {x: y for x, y in params.items()
                              if x in ['selector', 'roleArn']}
            elif selector == 'key-based':
                sub_params = {x: y for x, y in params.items()
                              if x in ['selector', 'secretKey', 'accessKey']}
            else:
                raise ValueError("Bad selector [%s] for platform [%s]",
                                 selector, platform)
        else:
            raise ValueError("Platform [%s] unsupported", platform)

    try:
        out = cb.V1credentialsApi().post_private_credential(
            body=cb.CredentialRequest(
                cloud_platform=service,
                description=name,
                name=name,
                parameters=sub_params
            ),
            **kwargs
        )
    except ApiException as e:
        log.info("Credential service returned an error, waiting 5 sec to retry")
        sleep(5)
        out = cb.V1credentialsApi().post_private_credential(
            body=cb.CredentialRequest(
                cloud_platform=service,
                description=name,
                name=name,
                parameters=sub_params
            ),
            **kwargs
        )
    if not out:
        raise ValueError("Could not create Credential with Cloudbreak")
    return out


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
    return create_credential(from_profile=True, name=name, **kwargs)


def delete_credential(identifier, **kwargs):
    return cb.V1credentialsApi().delete_credential(
        id=identifier,
        **kwargs
    )


def list_blueprints(bool_response=False, **kwargs):
    # Using this function as a test for the Cloudbreak Api being available
    try:
        bps = cb.V1blueprintsApi().get_publics_blueprint(
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
    return cb.V1blueprintsApi().post_private_blueprint(
        body=cb.BlueprintRequest(
            description=desc,
            name=name,
            ambari_blueprint=base64.b64encode(
                json.dumps(blueprint).encode()
            ).decode(),
            tags=tags
        ),
        **kwargs
    )


def delete_blueprint(bp_id, **kwargs):
    try:
        return cb.V1blueprintsApi().delete_blueprint(
            id=bp_id,
            **kwargs
        )
    except ApiException as e:
        raise e


def get_blueprint(identifier, identifier_type='name', **kwargs):
    if identifier_type == 'name':
        bp_info = cb.V1blueprintsApi().get_public_blueprint(
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
             name, desc, recipe_type, str(recipe)[:50], purge)
    if purge:
        target = [x.id for x in list_recipes() if x.name == name]
        if target:
            delete_recipe(target[0])
    if isinstance(recipe, bytes):
        submit = (base64.b64encode(recipe)).decode('utf-8')
    elif isinstance(recipe, six.string_types):
        submit = (base64.b64encode(bytes(recipe, 'utf-8'))).decode('utf-8')
    else:
        raise ValueError("Recipe Var Type not supported")
    return cb.V1recipesApi().post_private_recipe(
        # blueprint has to be a base64 encoded string for file upload
        body=cb.RecipeRequest(
            name=name,
            description=desc,
            recipe_type=recipe_type.upper(),
            content=submit
        ),
        **kwargs
    )


def list_recipes(**kwargs):
    return cb.V1recipesApi().get_publics_recipe(**kwargs)


def delete_recipe(rp_id, **kwargs):
    try:
        return cb.V1recipesApi().delete_recipe(
            id=rp_id,
            **kwargs
        )
    except ApiException as e:
        raise e


def list_image_catalogs(**kwargs):
    return cb.V1imagecatalogsApi().get_publics_image_catalogs(
        **kwargs
    )


def create_image_catalog(name, url, **kwargs):
    log.info("Creating Image Catalog [%s] at url [%s]",
             name, url)
    return cb.V1imagecatalogsApi().post_private_image_catalog(
        body=cb.ImageCatalogRequest(
            name=name,
            url=url,
        ),
        **kwargs
    )


def delete_image_catalog(name, **kwargs):
    assert isinstance(name, six.string_types)
    api = cb.V1imagecatalogsApi()
    return api.delete_public_image_catalog_by_name(
        name=name,
        **kwargs
    )


def get_images(platform, catalog=None, **kwargs):
    if catalog:
        return cb.V1imagecatalogsApi()\
            .get_public_images_by_provider_and_custom_image_catalog(
            name=catalog,
            platform=platform,
            **kwargs
        )
    return cb.V1imagecatalogsApi() \
        .get_images_by_provider(
        platform=platform,
        **kwargs
    )


def get_regions_by_credential(cred_name, **kwargs):
    return cb.V2connectorsApi().get_regions_by_credential_id(
        body=cb.PlatformResourceRequestJson(
            credential_name=cred_name,
            **kwargs
        )
    )


def get_custom_params(bp_name, **kwargs):
    return cb.V1utilApi().get_custom_parameters(
        body=cb.ParametersQueryRequest(
            blueprint_name=bp_name,
        ),
        **kwargs
    )


def list_stacks(**kwargs):
    return cb.V2stacksApi().get_publics_stack_v2(**kwargs)


def list_stacks_json(**kwargs):
    return cb.V2stacksApi().get_publics_stack_v2(_preload_content=False,**kwargs)


def list_templates(**kwargs):
    return cb.V1templatesApi().get_publics_template(**kwargs)


def list_templates_json(**kwargs):
    return cb.V1templatesApi().get_publics_template(_preload_content=False,**kwargs)


def get_stack_matrix(**kwargs):
    return cb.V1utilApi().get_stack_matrix_util(**kwargs)


def get_default_security_rules(**kwargs):
    return cb.V1securityrulesApi().get_default_security_rules(
        **kwargs
    )


def get_ssh_keys(params, **kwargs):
    body = cb.RecommendationRequestJson()
    _ = {body.__setattr__(x, y) for x, y in params.items()}
    return cb.V1connectorsApi().get_platform_s_sh_keys(
        body=body,
        **kwargs
    )


def list_mpacks(**kwargs):
    return cb.V1mpacksApi().get_public_management_packs(
        **kwargs
    )


def create_mpack(name, desc, url, purge_on_install, **kwargs):
    log.info("Creating MPack [%s] with desc [%s] from url [%s] with "
             "purge_on_install as [%s]",
             name, desc, url[:50], purge_on_install)
    return cb.V1mpacksApi().post_public_management_pack(
        body=cb.ManagementPackRequest(
            name=name,
            description=desc,
            mpack_url=url,
            purge=purge_on_install
        ),
        **kwargs
    )


def delete_mpack(name, **kwargs):
    assert isinstance(name, six.string_types)
    return cb.V1mpacksApi().delete_public_management_pack(
        name=name,
        **kwargs
    )


def list_dependencies():
    return {
        'blueprint': list_blueprints(),
        'recipe': list_recipes(),
        'catalog': list_image_catalogs(),
        'mpack': list_mpacks(),
        'auth': list_auth_confs(),
        'rds': list_rds_confs()
    }


def prep_dependencies(def_key, shortname=None):
    log.info("---- Preparing Dependencies for Definition [%s] with Name "
             "override [%s]", def_key, shortname)
    horton = utils.Horton()
    supported_resouces = ['recipe', 'blueprint', 'catalog', 'mpack', 'auth',
                          'rds']

    if horton.global_purge:
        purge = True
    elif 'purge' in horton.defs[def_key]:
        purge = horton.defs[def_key]['purge']
    else:
        purge = False

    fullname = horton.namespace + (shortname if shortname else def_key)
    deps = {}
    log.debug("Def like [%s]", json.dumps(horton.defs[def_key]))
    for res_type in [x for x in horton.defs[def_key].keys()
                     if x in supported_resouces]:
        log.debug("res_type like [%s]", res_type)
        res_defs = horton.defs[def_key][res_type]
        if not isinstance(res_defs, list):
            res_defs = [res_defs]
        for res in res_defs:
            log.debug("resource like [%s]", json.dumps(res))
            dep = None
            current = list_dependencies()
            if not res:
                # resource in def, but not populated
                log.info("Resource for res_type [%s] not in demo [%s], "
                         "skipping...", res_type, horton.defs[def_key]['name'])
                break
            log.info("checking Resource type [%s]", res_type)
            if 'name' in res and res['name']:
                if res_type == 'auth':
                    res_name = horton.namespace + 'auth'
                elif res_type not in ['blueprint']:
                    res_name = '-'.join([fullname, res['name']])
                else:
                    res_name = fullname
                res_name = res_name.rsplit('.')[0]
                log.info("Resource type [%s] has default Name [%s], using "
                         "ResName [%s]",
                         res_type, res['name'], res_name)
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
                    log.info("Resource [%s]:[%s] not found already loaded, loading...",
                             res_type, res_name)
            else:
                purge_resource(res_name, res_type)
            desc = res['desc'] if 'desc' in res else ''
            list_res_types = ['recipe', 'mpack', 'auth', 'rds']
            if res_type not in deps and res_type in list_res_types:
                # Treat everything as a list for simplicity
                deps[res_type] = []
            if res_type == 'blueprint':
                datalake = res['datalake'] if 'datalake' in res else False
                if datalake:
                    tags = {'shared_services_ready': True}
                else:
                    tags = None
                if dep:
                    deps[res_type] = dep[0]
                else:
                    deps[res_type] = \
                        create_blueprint(
                            desc=desc,
                            name=res_name,
                            blueprint=horton.resources[def_key][res['name']],
                            tags=tags
                        )
            if res_type == 'catalog':
                if dep:
                    deps[res_type] = dep[0]
                else:
                    deps[res_type] = \
                        create_image_catalog(
                        name=res_name,
                        url=horton.defs[def_key][res_type]['def']
                    )

            if res_type == 'recipe':
                if dep:
                    deps[res_type].append(dep[0])
                else:
                    deps[res_type].append(
                        create_recipe(
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
                if horton.cache['LDAPPUBLICIP']:
                    auth_configs = dict()
                    for conf in current[res_type]:
                        key = conf.__getattribute__("name")
                        auth_configs[key] = conf
                    if res_name in auth_configs:
                        deps[res_type].append(auth_configs[res_name])
                    else:
                        if 'params' in res:
                            params = res['params']
                        else:
                            params = None
                        deps[res_type].append(
                            create_auth_conf(
                                name=res_name,
                                host=horton.cache['LDAPPUBLICIP'],
                                params=params
                            )
                        )
                else:
                    log.info("Auth resource is requested in def but no DPS is "
                             "available, skipping...")
            if res_type == 'rds':
                if horton.cache['RDSPUBLICIP']:
                    rds_configs = dict()
                    if len(current[res_type]) > 0:
                        for conf in current[res_type]:
                            key = conf.__getattribute__("type")
                            rds_configs[key] = conf
                    if len(res['service']) > 0:
                        for rds_service in res['service']:
                            try:
                                if rds_configs[rds_service]:
                                    deps[res_type].append(
                                        rds_configs[rds_service])
                            except KeyError:
                                deps[res_type].append(
                                    create_rds_conf(
                                            name=res_name + rds_service,
                                            host=horton.cache['RDSPUBLICIP'],
                                            port=horton.cache['RDSPORT'],
                                            rds_type=rds_service,
                                            user_name=rds_service,
                                            password=rds_service
                                    )
                                )
                else:
                    log.info("Rds resource is requested in def but no DPS is "
                             "available, skipping...")
    horton.deps[fullname] = deps
    prep_images_dependency(def_key, fullname)
    log.info("Finding Gateway group from available groups like: %s",
             str(horton.defs[def_key]['group'].items()))
    gateway_group_name = [
        x for x, y in horton.defs[def_key]['group'].items()
        if y['type'] == 'GATEWAY'
    ]
    if not gateway_group_name:
        raise ValueError("Could not determine GATEWAY Group")
    horton.deps[fullname]['gateway'] = gateway_group_name[0]


def prep_images_dependency(def_key, fullname=None):
    horton = utils.Horton()
    log.info("Prepping valid images for demo spec")
    base_image_os = horton._getr('defs:' + def_key + ':infra:baseimage')
    cat_name = horton._getr('defs:' + def_key + ':catalog')
    images = get_images(
        catalog=cat_name,
        platform=horton.cbcred.cloud_platform
    )
    # base_image_os is an override in the yaml definition to select a specific
    # base image by operating system name
    # primarily used to force redhat7 instead of amazonlinux
    if not base_image_os:
        # if not over ride, try to select a prewarmed image matching stack def
        bp_content = utils.load(
            horton.deps[fullname]['blueprint'].ambari_blueprint,
            decode='base64'
        )
        stack_name = bp_content['Blueprints']['stack_name']
        stack_version = bp_content['Blueprints']['stack_version']
        try:
            ambari_version = horton._getr(
                'defs:' + def_key + ':infra:ambarirepo:version')
            stack_version_detail = horton._getr(
                'defs:' + def_key + ':infra:stackrepo:ver').split('-')[0]
        except AttributeError:
            log.info("Stack version override not set in yaml")
            ambari_version = stack_version_detail = None
        log.info("fetching stack matrix for name:version [%s]:[%s]",
                 stack_name, stack_version)
        stack_matrix = get_stack_matrix()
        stack_root = utils.get_val(
            stack_matrix,
            [stack_name.lower(), stack_version]
        )
        if not stack_root:
            log.warning("Stack %s %s not recognised by Cloudbreak",
                        stack_name, stack_version)
        log.info("Fetched images from Cloudbreak [%s]",
                 str(images.attribute_map)[:100]
                 )
        if ambari_version and stack_version_detail:
            images_by_type = [
                x for x in
                images.__getattribute__(stack_name.lower() + '_images')
                if x.version == ambari_version
                and x.stack_details.version == stack_version_detail
            ]
        else:
            images_by_type = [
                x for x in
                images.__getattribute__(
                    stack_name.lower() + '_images'
                ) if x.stack_details.version[:3] == stack_version
            ]
    else:
        images_by_type = []
        stack_version_detail = ''
        stack_root = None

    if base_image_os or len(images_by_type) == 0 and stack_version_detail:
        log.info("No matching prewarmed images found, trying base image...")
        if horton.cbcred.cloud_platform == 'AWS':
            # we will look for redhat7 on AWS over amazonlinux for preference
            base_image_os = base_image_os if base_image_os else 'redhat7'
            images_by_type = [
                x for x in images.base_images if x.os == base_image_os
            ]
        else:
            images_by_type = [
                x for x in images.base_images if x.default_image
            ]
    elif len(images_by_type) > 0:
        log.info("Prewarmed image matching blueprint is available...")
    else:
        raise ValueError("Could not find image matching blueprint ")
    valid_images = []
    assert len(images_by_type) > 0, "No Images found"
    for image in images_by_type:
        if stack_root:
            log.info("Stack recognised by Cloudbreak, checking versions")
            if type(image) == cb.BaseImageResponse:
                ver_check = [
                    x.version for x in image.__getattribute__(
                        '_'.join([stack_name.lower(), 'stacks'])
                    ) if x.version == stack_root.version
                ]
                if ver_check:
                    valid_images.append(image)
            elif type(image) == cb.ImageResponse:
                if image.stack_details.version[:3] == stack_version:
                    valid_images.append(image)
        else:
            log.info("Stack not recognised by Cloudbreak, using base image"
                     "like [%s]", images_by_type[0].repo)
            valid_images.append(images_by_type[0])

    if valid_images:
        log.info("found [%d] images matching requirements", len(valid_images))
        prewarmed = [
            x for x in valid_images
            if isinstance(x, cb.ImageResponse)
        ]
        if prewarmed:
            valid_images = prewarmed
        horton.deps[fullname]['images'] = valid_images
    else:
        raise ValueError("No Valid Images found for stack definition")


def prep_cluster(def_key, fullname=None):
    horton = utils.Horton()
    log.info("prepping stack cluster settings")
    tgt_os_name = horton.deps[fullname]['images'][0].os
    # cloning bundles can introduce duplicate mpack listings, so cleaning here and in loading deps
    if 'mpack' in horton.defs[def_key]:
        mpack_names = list(set(
            [
                x['name'] for x in horton.defs[def_key]['mpack']
            ]
        ))
        mpacks = [{'name': '-'.join([fullname, x])}
                  for x in mpack_names]
    else:
        mpacks = []
    bp_content = utils.load(
        horton.deps[fullname]['blueprint'].ambari_blueprint, decode='base64'
    )
    stack_name = bp_content['Blueprints']['stack_name']
    stack_version = bp_content['Blueprints']['stack_version']

    # Cloud Storage
    # if 'infra' in horton.defs[def_key] \
    #         and 'cloudstor' in horton.defs[def_key]['infra']:
    if horton._getr('defs:' + def_key + ':infra:cloudstor'):
        if horton.cbcred.cloud_platform == 'AWS':
            bucket = config.profile['bucket']
            if 'bucketrole' in config.profile:
                arn = config.profile['bucketrole']
            elif 'infraarn' in config.profile['platform']:
                arn = config.profile['platform']['infraarn']
            else:
                arn = None
            if arn:
                cloud_stor = cb.CloudStorageRequest(
                    s3=cb.S3CloudStorageParameters(
                        instance_profile=arn
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
                raise ValueError("AWS Cloudstor defined in Demo but no AWS "
                                 "Role found")
        elif horton.cbcred.cloud_platform == 'AZURE':
            wasb_suffix = '.blob.core.windows.net'
            storage_location = config.profile['bucket'].split('@')
            bucket = storage_location[1]
            container = storage_location[0]
            cloud_stor = cb.CloudStorageRequest(
                wasb=cb.WasbCloudStorageParameters(
                    account_key=config.profile['bucketkey'],
                    account_name=bucket
                ),
                locations=[]
            )
            for loc in horton.defs[def_key]['infra']['cloudstor']:
                cloud_stor.locations.append({
                    "value": "wasb://" + container
                             + '@' + bucket + wasb_suffix + loc['value'],
                    "propertyFile": loc['propfile'],
                    "propertyName": loc['propname']
                })
        elif horton.cbcred.cloud_platform == 'GCP':
            bucket = config.profile['bucket']
            cloud_stor = cb.CloudStorageRequest(
                gcs=cb.GcsCloudStorageParameters(
                    service_account_email=config.profile['bucketrole']
                ),
                locations=[]
            )
            for loc in horton.defs[def_key]['infra']['cloudstor']:
                cloud_stor.locations.append({
                    "value": "gs://" + bucket + loc['value'],
                    "propertyFile": loc['propfile'],
                    "propertyName": loc['propname']
                })
        else:
            raise ValueError("Cloud Storage on Platform {0} not supported"
                             .format(horton.cbcred.cloud_platform))
    else:
        log.info("cloudstorage not defined in demo, skipping...")
        cloud_stor = None
    log.info("using mpack [%s]", str(mpacks))

    cluster_req = cb.ClusterV2Request(
                ambari=cb.AmbariV2Request(
                    blueprint_name=horton.deps[fullname]['blueprint'].name,
                    ambari_stack_details=cb.AmbariStackDetails(
                        version=stack_version,
                        verify=False,
                        enable_gpl_repo=False,
                        stack=stack_name,
                        os=tgt_os_name,
                        mpacks=mpacks
                    ),
                    user_name=config.profile['username'],
                    password=security.get_secret('ADMINPASSWORD'),
                    validate_blueprint=False,  # Hardcoded?
                    ambari_security_master_key=security.get_secret(
                        'MASTERKEY'),
                    kerberos=None,
                    enable_security=False  # Hardcoded?
                ),
                cloud_storage=cloud_stor
            )
    if 'auth' in horton.defs[def_key] \
            and 'name' in horton.defs[def_key]['auth']:
        cluster_req.ldap_config_name = horton.namespace + "auth"
        cluster_req.proxy_name = None
    if 'rds' in horton.defs[def_key]:
        if len(horton.deps[fullname]['rds']) > 0:
            rds_config_names = []
            for rds_config in horton.deps[fullname]['rds']:
                rds_type = rds_config.__getattribute__("type")
                if horton.defs[def_key]['rds']['service'][rds_type]:
                    rds_name = rds_config.__getattribute__("name")
                    rds_config_names.append(rds_name)
            cluster_req.rds_config_names = rds_config_names
    if 'attached' in horton.defs[def_key] and horton.defs[def_key]['attached']:
        if 'SHAREDSERVICESNAME' in horton.cache:
            shared_service_cluster_name = horton.cache['SHAREDSERVICESNAME']
            cluster_req.shared_service = cb.SharedService(shared_cluster=shared_service_cluster_name)
        else:
            raise ValueError("attached is set to true but no SHAREDSERVICESNAME key in Horton.cache...")
    if 'proxy' in horton.defs[def_key] and horton.defs[def_key]['proxy']:
        cluster_req.ambari.gateway = cb.GatewayJson(
            enable_gateway=True,
            sso_type=horton.defs[def_key]['proxy']['sso'],
            topologies=[
                cb.GatewayTopologyJson(
                    topology_name='dp-proxy',
                    exposed_services=horton.defs[def_key]['proxy']['services']
                )
            ]
        )
    # if 'stackrepo' in horton.defs[def_key]['infra']:
    if horton._getr('defs:' + def_key + ':infra:stackrepo'):
        cluster_req.ambari.ambari_stack_details.repository_version = \
            horton.defs[def_key]['infra']['stackrepo']['ver']
        cluster_req.ambari.ambari_stack_details.version_definition_file_url = \
            horton.defs[def_key]['infra']['stackrepo']['url']
    # if 'ambarirepo' in horton.defs[def_key]['infra']:
    if horton._getr('defs:' + def_key + ':infra:ambarirepo'):
        ambari_repo = {
            x: y for x, y
            in horton.defs[def_key]['infra']['ambarirepo'].items()
        }
        cluster_req.ambari.ambari_repo_details_json = ambari_repo
    if horton._getr('defs:' + def_key + ':krb:mode'):
    # if 'krb' in horton.defs[def_key]:
    #     if horton.defs[def_key]['krb'] \
    #             and 'mode' in horton.defs[def_key]['krb']:
        if not horton.defs[def_key]['krb']['mode'] == 'test':
            raise ValueError("Kerberising in Cloudbreak Test Mode Only")
        cluster_req.ambari.enable_security = True
        cluster_req.ambari.kerberos = cb.KerberosRequest(
            admin=config.profile['username'],
            password=security.get_secret('ADMINPASSWORD'),
            master_key=security.get_secret('MASTERKEY'),
            tcp_allowed=False
        )
    return cluster_req


def prep_instance_groups(def_key, fullname):
    horton = utils.Horton()
    log.info("Prepping instance groups")
    try:
        region = horton.specs[fullname].placement.region
        avzone = horton.specs[fullname].placement.availability_zone
    except AttributeError:
        if 'zone' in horton.cbd.extra:
            region = horton.cbd.extra['zone'].extra['region']
            avzone = horton.cbd.extra['zone'].name
        else:
            # Defaulting to OpenStack defaults as a backup
            region = 'RegionOne'
            avzone = horton.cbd.extra['availability_zone']

    log.info("Fetching Infrastructure recommendation for "
             "credential[%s]:blueprint[%s]:region[%s]:availability zone[%s]",
             horton.cbcred.name, horton.deps[fullname]['blueprint'].name,
             region, avzone)

    recs = cb.V1connectorsApi().create_recommendation(
        body=cb.RecommendationRequestJson(
            availability_zone=avzone,
            region=region,
            blueprint_id=horton.deps[fullname]['blueprint'].id,
            credential_id=horton.cbcred.id
        )
    )
    log.info("Handling Security Rules")
    lib_c_session = infra.create_libcloud_session()
    if horton.cbcred.cloud_platform == 'AWS':
        sec_group = horton.cbd.extra['groups'][0]['group_id']
    elif horton.cbcred.cloud_platform == 'AZURE':
        sec_group = lib_c_session.ex_list_network_security_groups(
            resource_group=horton.namespace + 'cloudbreak-group')[0].id
    elif horton.cbcred.cloud_platform == 'GCP':
        sec_group = lib_c_session.ex_get_firewall(
            name=horton.namespace + 'cloudbreak-firewall').name
    elif horton.cbcred.cloud_platform == 'OPENSTACK':
        sec_group = lib_c_session.ex_get_node_security_groups(horton.cbd)[0].id
    else:
        raise ValueError("Only Platforms AWS, AZURE, OpenStack, and GCP supported")
    if sec_group:
        # Predefined Security Group
        sec_group = cb.SecurityGroupResponse(
            security_group_id=sec_group,
            cloud_platform=horton.cbcred.cloud_platform
        )
    else:
        raise ValueError("Network Security Group not Provided")
    groups = []
    log.info("found recommendations for instance groups [%s]",
             str(recs.recommendations.keys()))
    for group in recs.recommendations.keys():
        log.info("handling group [%s]", group)
        rec = recs.recommendations[group]
        group_def = horton.defs[def_key]['group'].get(group)
        if group_def:
            log.info("Group [%s] found in demo def, proceeding...", group)
        else:
            log.info("Group [%s] not in demo def, using defaults...", group)
            group_def = {}
        nodes = group_def['nodes'] if 'nodes' in group_def else 1
        machine = group_def['machine'] if 'machine' in group_def else None
        log.info("Finding a machine type matching spec [%s]", machine)
        machine_range = machine.split('-')
        machine_min = machine_range[0]
        machine_max = machine_range[1]
        min_cpu = int(machine_min.split('x')[0])
        max_cpu = int(machine_max.split('x')[0])
        min_mem = float(machine_min.split('x')[1])
        max_mem = float(machine_max.split('x')[1])
        sizes = recs.virtual_machines
        machines_by_size = [
            x for x in sizes
            if min_cpu <= int(x.vm_type_meta_json.properties['Cpu']) <= max_cpu
            and min_mem <= float(x.vm_type_meta_json.properties['Memory']) <= max_mem
        ]
        if not machines_by_size:
            raise ValueError("Couldn't find a VM of the right size")
        else:
            if horton.cbcred.cloud_platform == 'AZURE':
                machines = [
                    x for x in machines_by_size
                    if ('Standard_D' in x.value or 'Standard_DS' in x.value)
                    and 'v2' in x.value
                    and 'Promo' not in x.value
                ]
            elif horton.cbcred.cloud_platform == 'AWS':
                machines = [
                    x for x in machines_by_size
                    if 'm4.' in x.value or 'm5.' in x.value
                ]
            else:  # GCP
                machines = [
                    x for x in machines_by_size
                    if 'n' in x.value
                ]
            if machines:
                machine = machines[0].value
            else:
                log.info("Machine list does not contain expected types: %s", str(machines_by_size))
                raise ValueError("Could not find a machine type matching demo spec for %s", group)

        if 'recipe' in group_def and group_def['recipe'] is not None:
            # convert to set and back again to only use unique list of recipes as duplicates may be introduced during
            # merging of demos
            recipes = list(set(['-'.join([fullname, x]) for x in group_def['recipe']]))
        else:
            recipes = []
        log.info("Using Recipe list [%s]", str(recipes))
        if horton.deps[fullname]['gateway'] == group:
            # This is the Ambari group
            typ = 'GATEWAY'
        else:
            typ = 'CORE'
        disk_types = [x.name for x in recs.disk_responses]
        vol_types = sorted([
            x for x in disk_types
            if ('standard' in x.lower() or 'gp2' in x.lower())
            and 'GRS' not in x]
        )
        if len(vol_types) == 0:
            vol_type = disk_types[0]
        else:
            vol_type = vol_types[0]
        if 'rootvol' in group_def:
            root_vol_size = group_def['rootvol']
        else:
            root_vol_size = rec.vm_type_meta_json.properties[
                'recommendedRootVolumeSize']
        log.info("using root vol size [%s]", root_vol_size)
        if 'vols' in group_def:
            vol_count = group_def['vols'].split('x')[0]
            vol_size = group_def['vols'].split('x')[1]
        else:
            vol_count = rec.vm_type_meta_json.properties[
                            'recommendedvolumeCount']
            vol_size = rec.vm_type_meta_json.properties[
                            'recommendedvolumeSizeGB']
        log.info("using [%s] volumes of size [%s]", vol_count, vol_size)
        item = cb.InstanceGroupsV2(
                    security_group=sec_group,
                    template=cb.TemplateV2Request(
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
    horton = utils.Horton()
    fullname = horton.namespace + (name if name else def_key)
    log.info("Preparing Spec for Def [%s] as Name [%s]", def_key, fullname)
    cat_name = horton._getr('defs:' + def_key + ':catalog')
    if horton.global_purge or horton.defs[def_key]['purge']:
        stack = [x for x in list_stacks() if x.name == fullname]
        if stack:
            delete_stack(stack[0].id)
    # Sequence matters here, as some later params are have deps in earlier
    # Which also means you can't be clever and define it in one big call
    # Making Placeholder
    horton.specs[fullname] = cb.StackV2Request(
        general='', instance_groups=''
    )
    
    tags = utils.resolve_tags(instance_name=fullname, owner=config.profile['tags']['owner'])
    
    horton.specs[fullname].tags = {'userDefinedTags': tags}
    
    horton.specs[fullname].general = cb.GeneralSettings(
            credential_name=horton.cbcred.name,
            name=fullname
        )
    horton.specs[fullname].image_settings = \
        cb.ImageSettings(
            image_catalog=cat_name,
            image_id=horton.deps[fullname]['images'][0].uuid
        )
    if horton.cbcred.cloud_platform == 'AWS':
        horton.specs[fullname].stack_authentication = \
            cb.StackAuthenticationResponse(
                public_key_id=config.profile['sshkey_name']
        )
        horton.specs[fullname].placement = cb.PlacementSettings(
            region=horton.cbd.extra['availability'][:-1],
            availability_zone=horton.cbd.extra['availability']
        )
        horton.specs[fullname].network = cb.NetworkV2Request(
            parameters={
                'subnetId': horton.cbd.extra['subnet_id'],
                'vpcId': horton.cbd.extra['vpc_id']
            }
        )
    elif horton.cbcred.cloud_platform == 'AZURE':
        horton.specs[fullname].stack_authentication = \
            cb.StackAuthenticationResponse(
                    public_key=config.profile['sshkey_pub']
            )
        horton.specs[fullname].placement = cb.PlacementSettings(
            region=config.profile['platform']['region'],
            availability_zone=config.profile['platform']['region']
        )
        horton.specs[fullname].network = cb.NetworkV2Request(
            parameters={
                'subnetId': horton.namespace + 'cloudbreak-subnet',
                'networkId': horton.namespace + 'cloudbreak-network',
                'resourceGroupName': horton.namespace + 'cloudbreak-group'
            }
        )
    elif horton.cbcred.cloud_platform == 'GCP':
        horton.specs[fullname].stack_authentication = \
            cb.StackAuthenticationResponse(
                    public_key=config.profile['sshkey_pub']
            )
        horton.specs[fullname].placement = cb.PlacementSettings(
            region=config.profile['platform']['region'],
            availability_zone=horton.cbd.extra['zone'].name
        )
        nic_info = horton.cbd.extra['networkInterfaces'][0]
        subnet_path = nic_info['subnetwork'].split('/')
        subnet_id = subnet_path[len(subnet_path)-1]
        network_path = nic_info['network'].split('/')
        network_id = network_path[len(network_path)-1]
        horton.specs[fullname].network = cb.NetworkV2Request(
            parameters={
                'subnetId': subnet_id,
                'networkId': network_id
            }
        )

    horton.specs[fullname].cluster = prep_cluster(def_key, fullname)
    log.info("Checking Inputs for Blueprint")
    if 'input' in horton.defs[def_key]:
        horton.specs[fullname].inputs = {}
        for input_key, input_val in horton.defs[def_key]['input'].items():
            if isinstance(input_val, six.string_types):
                if input_val.startswith('CALL:'):
                    log.info("Input uses Command [%s] for Param [%s]",
                             input_val, input_key)
                    input_val = input_val.split(':')[-1]
                    this_module = sys.modules[__name__]
                    tgt_module = getattr(
                        this_module,
                        input_val.split('.')[0]
                    )
                    func = getattr(
                        tgt_module,
                        input_val.split('.')[1]
                    )
                    input_val = func()
                elif input_val.startswith('GET:'):
                    log.info("Input uses Command [%s] for Param [%s]",
                             input_val, input_key)
                    input_val = input_val.split(':')[-1]
                    import whoville
                    input_val = utils.get_val(whoville, input_val, '.')
                elif input_val.startswith('GETCACHE:'):
                    log.info("Input uses Command [%s] for Param [%s]",
                             input_val, input_key)
                    input_val = input_val.split(':')[-1]
                    input_val = horton.cache[input_val]
            horton.specs[fullname].inputs[input_key] = input_val
    else:
        log.info("No Inputs found, skipping...")
    horton.specs[fullname].instance_groups = prep_instance_groups(
        def_key, fullname
    )


def create_stack(name, wait=False, purge=False, **kwargs):
    log.info("Running Create Stack [%s] with wait [%s] and purge [%s]",
             name, wait, purge)
    horton = utils.Horton()
    start_ts = datetime.utcnow()
    stack = [x for x in list_stacks() if x.name == name]
    if stack:
        log.info("Stack [%s] already Exists", name)
        stack = stack[0]
        if horton.global_purge or purge:
            log.info("Purge is True, deleting existing Stack", name)
            delete_stack(stack.id)
        elif any(s in stack.status for s in ['FAILED', 'STOP']) \
                or any(s in stack.cluster.status for s in ['FAILED', 'STOP']):
            log.info("Stack [%s] in bad state [%s], recreating",
                     name, str(stack.status + stack.cluster.status))
            delete_stack(stack.id)
        elif stack.status == 'DELETE_IN_PROGRESS':
            log.info("Stack is being deleted, waiting for completion")
            utils.wait_to_complete(
                monitor_event_stream,
                start_ts=start_ts,
                identity=('stack_name', name),
                target_event=('stack_status', 'DELETE_COMPLETED'),
                valid_events=['DELETE_IN_PROGRESS'],
                whoville_delay=15,
                whoville_max_wait=config.long_max_wait
            )
        else:
            log.info("Stack [%s] Exists in State [%s] and Purge is False,"
                     " returning Existing Stack", name, stack.cluster.status)
            return stack
    log.info("Stack [%s] not found, Creating", name)
    resp = cb.V2stacksApi().post_private_stack_v2(
        body=horton.specs[name],
        **kwargs
    )
    horton.stacks[name] = resp
    if wait:
        utils.wait_to_complete(
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
             "[%s]", int(stack_id), str(force), str(wait))
    start_ts = datetime.utcnow()
    resp = cb.V2stacksApi().delete_stack_v2(
        id=stack_id,
        forced=force,
        **kwargs
    )
    if wait:
        # max wait 600 - Azure is slower than an asthmatic grandma at Costco
        utils.wait_to_complete(
            monitor_event_stream,
            start_ts=start_ts,
            identity=('stack_id', stack_id),
            target_event=('stack_status', 'DELETE_COMPLETED'),
            valid_events=['DELETE_IN_PROGRESS'],
            whoville_delay=20,
            whoville_max_wait=600
        )
    return resp


def monitor_event_stream(start_ts, identity, target_event, valid_events):
    log.info("Monitoring event stream from [%s] for Event [%s] for Identity "
             "[%s] against Valid Events [%s]",
             str(start_ts), str(target_event), str(identity), str(valid_events)
             )
    events = get_events(
        start_ts=start_ts,
        select_by=identity,
    )
    event_set = set([x.__getattribute__(target_event[0])
                     for x in events])
    if not event_set:
        log.warning("No Events received in the last interval, if this "
                    "persists please check the identity and target event "
                    "against Cloudbreak")
    else:
        log.info("Retrieved updated events %s, waiting for target event %s",
                 str(event_set), target_event[0])
    if target_event[1] in event_set:
        return True
    valid_test = [
        x for x in events
        if x.__getattribute__(target_event[0]) not in valid_events
    ]
    if valid_test:
        raise ValueError(
            "Found Event {0} for Identity {1} which is not in Valid Event "
            "list {2}. Error message is: {3}".format(
                str(valid_test[0].__getattribute__(target_event[0])),
                str(identity),
                str(valid_events),
                str(valid_test[0].event_message)
            )
        )
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
        events = cb.V1eventsApi().get_events(
            since=submit_ts)
    else:
        events = cb.V1eventsApi().get_events()
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
                datetime(1970, 1, 1) +
                timedelta(milliseconds=e.event_timestamp)
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
                 'recipe', 'catalog', 'auth', 'rds']
    if res_type in res_types:
        # Set the param to identify the target resource

        if res_type in ['catalog', 'mpack', 'auth', 'rds']:
            del_arg = 'name'
        else:
            del_arg = 'id'
        # rename if necessary

        if res_type == 'catalog':
            p_res_type = 'image_catalog'
        elif res_type == 'auth':
            p_res_type = 'auth_conf'
        elif res_type == 'rds':
            p_res_type = 'rds_conf'
        else:
            p_res_type = res_type

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
    target = [x for x
              in getattr(sys.modules[__name__], 'list_' + p_res_type + 's')()
              if x.name == res_name]
    if not target:
        log.info("Resource named [%s] of Type [%s] not found, skipping delete",
                 res_name, p_res_type)
        return
    try:
        log.info("Attempting Delete of [%s]:[%s] identified by [%s]",
                 p_res_type, res_name, del_arg)
        getattr(sys.modules[__name__], 'delete_' + p_res_type)(
            target[0].__getattribute__(del_arg),
            **params
        )
        log.info("Deleted [%s]:[%s] identified by [%s]",
                 p_res_type, res_name, del_arg)
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


def purge_cloudbreak(for_reals, ns=''):
    horton = utils.Horton()
    if not for_reals:
        raise ValueError("Cowardly not purging Cloudbreak as you didn't say "
                         "for reals. Please check function definition")
    # Stacks first because of dependencies
    log.info("Purging stacks")
    [delete_stack(x.id, force=True)
     for x in list_stacks()
     if ns in x.name]
    # Then other stuff
    # Images
    log.info("Purging Images")
    [delete_image_catalog(x.name)
     for x in list_image_catalogs()
     if x.used_as_default is False and horton.namespace in x.name]
    # Blueprints
    log.info("Purging Blueprints")
    [delete_blueprint(x.id)
     for x in list_blueprints()
     if ns in x.name]
    # Recipes
    log.info("Purging Recipes")
    [delete_recipe(x.id)
     for x in list_recipes()
     if ns in x.name]
    # Credentials
    log.info("Purging Credentials")
    [delete_credential(x.id)
     for x in list_credentials()
     if ns in x.name]
    # Mpacks
    log.info("Purging MPacks")
    [delete_mpack(x.name)
     for x in list_mpacks()
     if ns in x.name]
    # Auths
    log.info("Purging Auths")
    [delete_auth_conf(x.name)
     for x in list_auth_confs()
     if ns in x.name]


def list_auth_confs():
    return cb.V1ldapApi().get_publics_ldap()


def delete_auth_conf(auth_name):
    return cb.V1ldapApi().delete_private_ldap(auth_name)


def create_auth_conf(name, host, params=None):
    horton = utils.Horton()
    host_id = host if host != 'DPSPUBLICIP' else horton.cache['DPSPUBLICIP']
    obj = cb.LdapConfigRequest(
        name=name,
        server_host=host_id,
        server_port=33389,
        directory_type='LDAP',
        protocol='ldap',
        bind_dn='uid=admin,ou=people,dc=hadoop,dc=apache,dc=org',
        bind_password=security.get_secret('ADMINPASSWORD'),
        user_search_base='ou=people,dc=hadoop,dc=apache,dc=org',
        user_dn_pattern='uid={0},ou=people,dc=hadoop,dc=apache,dc=org',
        user_object_class='person',
        user_name_attribute='uid',
        group_search_base='ou=groups,dc=hadoop,dc=apache,dc=org',
        group_object_class='groupOfNames',
        group_member_attribute='member',
        group_name_attribute='cn',
        domain='',
        admin_group=''
    )
    if params:
        for k, v in params.items():
            obj.__setattr__(k, v)
    return cb.V1ldapApi().post_private_ldap(
        body=obj
    )


def list_rds_confs():
    return cb.V1rdsconfigsApi().get_privates_rds()


def delete_rds_conf(rds_name):
    return cb.V1rdsconfigsApi().delete_private_rds(rds_name)


def create_rds_conf(name, host, port, rds_type, user_name, password):
    obj = cb.RdsConfig(
        name=name,
        connection_url="jdbc:postgresql://"+host+":"+str(port)+"/"+rds_type,
        type=rds_type,
        connection_user_name=user_name,
        connection_password=password
    )

    return cb.V1rdsconfigsApi().post_private_rds(
        body=obj
    )


def wait_for_event(name, field, state, start_ts, wait):
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
        stack = stack[0]
        current_level = event_key[stack.status]
        if current_level >= target_level:
            log.info("Stack [%s] at State [%s], which is >= [%s], "
                     "Returning Success", name, stack.status, state)
            return
    utils.wait_to_complete(
        monitor_event_stream,
        start_ts=start_ts,
        identity=('stack_name', name),
        target_event=(field, state),
        valid_events=[
            'UPDATE_IN_PROGRESS', 'BILLING_STARTED', 'AVAILABLE',
            'CREATE_IN_PROGRESS', 'DELETE_IN_PROGRESS', 'DELETE_COMPLETED',
            'BILLING_TERMINATED', 'REQUESTED'
        ],
        whoville_delay=15,
        whoville_max_wait=wait
    )


def add_security_rule(cidr, start, end, protocol, description=None):
    horton = utils.Horton()
    description = description if description else 'None'
    log.info("Adding Security Rule with: %s %s %s %s",
             str(protocol), str(start), str(end), str(cidr))
    if horton.cbcred.cloud_platform == 'AWS':
        infra.add_sec_rule_to_ec2_group(
            session=infra.create_libcloud_session(),
            rule={
                'protocol': protocol,
                'from_port': start,
                'to_port': end,
                'cidr_ips': [cidr],
                'description': description
            },
            sec_group_id=horton.cbd.extra['groups'][0]['group_id']
        )
    elif horton.cbcred.cloud_platform == 'AZURE':
        token = infra.get_azure_token()
        a_session = infra.create_azure_session(token, 'network')
        res_group_name = horton.namespace + 'cloudbreak-group'
        sec_group = [
            x for x in a_session.network_security_groups.list(res_group_name)
        ][0]
        sec_group_name = sec_group.name
        # standard fields excepting priority
        rule_fingerprint = [
            'protocol', 'source_port_range', 'destination_port_range',
            'direction', 'source_address_prefix', 'access',
            'destination_address_prefix'
        ]
        current_rules = [
            {
                k: v for k, v in x.as_dict().items()
                if k in rule_fingerprint
            } for x in sec_group.security_rules
        ]
        new_rule = {
                'protocol': 'Tcp',
                'source_port_range': '*',
                'destination_port_range': str(start)+'-'+str(end),
                'source_address_prefix': cidr,
                'destination_address_prefix': '*',
                'access': 'Allow',
                'direction': 'Inbound'
            }
        if new_rule in current_rules:
            log.info("Rule already exists, skipping...")
            return
        # if rule is new, find next available priority
        priorities = [
            x.priority for x in sec_group.security_rules
        ]
        if priorities:
            priority = sorted(priorities)[-1] + 1
        else:
            priority = 100
        new_rule['priority'] = priority
        security_rule_name = '-'.join(
            [str(start),
             str(end),
             str(cidr).replace('.','-').replace('/','-')
             ]
        )
        log.info("Creating Azure rule [%s] in security group [%s]",
                 security_rule_name, sec_group_name)
        infra.add_sec_rule_azure(
            session=a_session,
            resource_group=res_group_name,
            sec_group_name=sec_group_name,
            security_rule_name=security_rule_name,
            security_rule_parameters=new_rule
        )
    elif horton.cbcred.cloud_platform == 'GCP':
        number_of_ports = end - start
        if number_of_ports < 100:
            session = infra.create_libcloud_session()
            rule = {'IPProtocol': 'tcp',
                    'ports': [str(start) + '-' + str(end)]}
            firewall = session.ex_get_firewall(
                name=horton.namespace + 'cloudbreak-firewall')
            firewall.allowed.append(rule)
            session.ex_update_firewall(firewall)
        else:
            log.info("Due to firewall rule structure of GCP, this action "
                     "would cause >= 100 ports to be open to "
                     "0.0.0.0... skipping")
    else:
        raise ValueError("Cloud Platform not Supported")


def write_cache(name, item, cache_key):
    log.info("Writing [%s] from [%s] to Horton Cache key [%s]",
             item, name, cache_key)
    horton = utils.Horton()
    if item in ['public_ip']:
        stack = [x for x in list_stacks()
                 if x.name == name][0]
        if stack:
            group = [
                x for x in stack.instance_groups
                if x.type == 'GATEWAY'][0]
            if group:
                instance = [
                    x for x in group.metadata if x.ambari_server is True][0]
                horton.cache[cache_key] = instance.__getattribute__(item)
    elif item in ['private_ip']:
        stack = [x for x in list_stacks()
                 if x.name == name][0]
        if stack:
            group = [
                x for x in stack.instance_groups
                if x.type == 'GATEWAY'][0]
            if group:
                instance = [
                    x for x in group.metadata if x.ambari_server is True][0]
                horton.cache[cache_key] = instance.__getattribute__(item)
    elif item in ['shared_services']:
        stack = [x for x in list_stacks() if x.user_defined_tags['datalake'] == 'true'][0]
        if stack:
            horton.cache[cache_key] = stack.cluster.name
    elif item in ['cdsw_ip']:
        stack = [x for x in list_stacks() if x.name == name][0]
        if stack:
            group = [
                x for x in stack.instance_groups
                if 'cdsw' in x.group][0]
            if group:
                instance = [
                    x for x in group.metadata if 'cdsw' in x.instance_group][0]
                horton.cache[cache_key] = instance.__getattribute__('public_ip')
            else:
                raise ValueError("CDSWIP requested but not found")
        else:
            raise ValueError("CDSWIP requested but not found")
    else:
        # write literal value to cache
        horton.cache[cache_key] = item


def replace_string_in_resource(name, target, cache_key):
    horton = utils.Horton()
    horton.resources[name][target].replace(cache_key, horton.cache[cache_key])


def check_cloudbreak_version(version=None):
    version = version if version else config.cb_min_ver
    return cb.V1utilApi().check_client_version(version)
