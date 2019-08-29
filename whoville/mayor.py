# -*- coding: utf-8 -*-

"""
Populates a provided Cloudbreak Instance with resources for Demos

Warnings:
    Experimental
"""

from __future__ import absolute_import as _abs_imp
import logging
import re as _re
import json
import os
from time import sleep as _sleep
from datetime import datetime as _dt
from whoville import config, utils, security, infra, deploy, actions, director
from flask import Flask, request, Response


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


# 'horton' is a shared state function to make deployment more readable
# to non-python users
horton = utils.Horton()
app = Flask(__name__)


def init_whoville_service():
    init_start_ts = _dt.utcnow()
    log.info("------------- Initialising Whoville Deployment Service at [%s]",
             init_start_ts)
    log.info("------------- Validating Profile")
    utils.validate_profile()
    log.info("------------- Loading Default Resources")
    default_resources = []
    for d in os.listdir(
            os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources'))):
        if d[0] == 'v':
            default_resources.append(d)
    for d in default_resources:
        horton.resources.update(
            utils.load_resources_from_files(
                os.path.abspath(os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), 'resources', d)
                )
            )
        )
    log.info("------------- Fetching Resources from Profile Definitions")
    if 'resources' in config.profile and config.profile['resources']:
        for res_def in config.profile['resources']:
            if res_def['loc'] == 'local':
                log.info("Loading resources from Local path [%s]",
                         res_def['uri'])
                horton.resources.update(utils.load_resources_from_files(
                    res_def['uri']
                ))
            elif res_def['loc'] == 'github':
                log.info("Loading resources from Github Repo [%s]",
                         res_def['repo'])
                horton.resources.update(utils.load_resources_from_github(
                    repo_name=res_def['repo'],
                    username=config.profile['githubuser'],
                    token=config.profile['githubtoken'],
                    tgt_dir=res_def['subdir']
                ))
            else:
                raise ValueError("Resource Location [%s] Unsupported",
                                 res_def['loc'])
    else:
        log.info("Unable to find additional Demo resources")
    key_test = _re.compile(r'[a-z0-9-.]')
    for def_key, res_list in horton.resources.items():
        log.debug('def_key [%s] res_list [%s]', def_key, res_list)
        if not def_key[0] == '.':
            # Skipping any dot files or directories as unsafe
            for res_filename, res_content in res_list.items():
                if not bool(key_test.match(res_filename)):
                    raise ValueError("Resource Name must only contain 0-9 a-z - .")
            horton.defs[def_key] = res_list[def_key + '.yaml']
    init_finish_ts = _dt.utcnow()
    diff_ts = init_finish_ts - init_start_ts
    log.info("Completed Service Init at [%s] after [%d] seconds",
             init_finish_ts, diff_ts.seconds)


def init_k8svm_infra(create_wait=0):
    init_start_ts = _dt.utcnow()
    log.info("------------- Getting Environment at [%s]",
             init_start_ts)
    horton.k8svm = infra.get_k8svm(
        purge=horton.global_purge,
        create_wait=create_wait
    )


def init_cbreak_infra(create=True, create_wait=0):
    init_start_ts = _dt.utcnow()
    log.info("------------- Getting Environment at [%s]",
             init_start_ts)
    horton.cbd = infra.get_cloudbreak(
        purge=horton.global_purge,
        create_wait=create_wait,
        create=create
    )
    if not horton.cbd:
        if create:
            # Create has failed, throw error
            raise ValueError("Cloudbreak Create requested but failed, exiting...")
        else:
            return None
    else:
        log.info("Found existing Cloudbreak in Namespace, connecting...")
    log.info("------------- Connecting to Environment")
    if horton.cbd.public_ips:
        public_ip = horton.cbd.public_ips[0]
    else:
        public_ip = horton.cbd.name + config.profile['platform']['domain']
    cbd_url = 'https://' + public_ip + '/cb/api'
    cad_url = 'https://' + public_ip + ':7189'
    log.info("Setting Cloudbreak endpoint to %s", cbd_url)
    utils.set_endpoint(cbd_url)
    log.info("Setting Altus Director endpoint to %s", cad_url)
    utils.set_endpoint(cad_url)
    log.info("------------- Authenticating to Cloudbreak")
    email = config.profile['email'] if 'email' in config.profile else 'admin@example.com'
    username = config.profile['username'] if 'username' in config.profile else 'admin'
    cbd_auth_success = security.service_login(
            service='cloudbreak',
            username=email,
            password=security.get_secret('ADMINPASSWORD'),
            bool_response=False
        )
    if not cbd_auth_success:
        raise ConnectionError("Couldn't login to Cloudbreak")
    else:
        log.info('Logged into Cloudbreak at [%s]', cbd_url)
    log.info("------------- Authenticating to Altus Director")
    cad_auth_success = security.service_login(
        service='director',
        username=username,
        password=security.get_secret('ADMINPASSWORD'),
        bool_response=False
    )
    if not cad_auth_success:
        raise ConnectionError("Couldn't login to Director")
    else:
        log.info('Logged into Director at [%s]', cad_url)
    # Cloudbreak may have just booted and not be ready for queries yet
    log.info("Waiting for Cloudbreak API Calls to be available")
    utils.wait_to_complete(
        deploy.list_blueprints,
        bool_response=True,
        whoville_delay=5,
        whoville_max_wait=120
    )
    # Director may not be ready for queries yet
    log.info("Waiting for Altus Director API Calls to be available")
    utils.wait_to_complete(
        director.list_environments,
        bool_response=True,
        whoville_delay=5,
        whoville_max_wait=120
    )
    # Validating Cloudbreak version
    if not deploy.check_cloudbreak_version():
        raise ValueError("Cloudbreak server is older than configured minimum version of %s",
                         str(config.cb_ver))
    # Creating Environment Credentials
    log.info("------------- Setting Deployment Credential")
    log.info("Ensuring Credential for Cloudbreak")
    horton.cbcred = deploy.get_credential(
        config.profile['namespace'] + 'credential',
        create=True,
        purge=horton.global_purge
    )
    log.info("Ensuring Environment Credential for Director")
    horton.cdcred = director.get_environment()
    init_finish_ts = _dt.utcnow()
    diff_ts = init_finish_ts - init_start_ts
    log.info("Completed Infrastructure Init at [%s] after [%d] seconds",
             init_finish_ts, diff_ts.seconds)


def resolve_bundle_reqs(def_key):
    log.info("Handling bundle requirements")
    reqs = horton._getr('defs:' + def_key + ':req')
    if not reqs:
        log.info("Bundle requirements not explicitly set, defaulting to Cloudbreak and Director")
        # Default to Cloudbreak / Director service
        if not horton.cbcred:
            init_cbreak_infra()
    else:
        # Work through deps declaration
        log.info("Bundle requirements found, processing...")
        if 'k8svm' in reqs.lower():
            log.info("Found k8s on VM requirement, processing...")
            if not horton.k8svm:
                log.info("K8s on VM not not found, deploying...")
                init_k8svm_infra()
            else:
                log.info("K8s on VM found for provider, continuing...")
        if 'k8ske' in reqs.lower():
            log.info("Found k8s on K8s Engine requirement, processing...")
            if not horton.k8ske:
                log.info("K8s on K8s Engine not not found, deploying...")
                pass
            else:
                log.info("K8s on K8s Engine found for provider, continuing...")
        if 'cb' in reqs.lower() or 'ad' in reqs.lower():
            log.info("Found explicit Cloudbreak/Director requirement, processing...")
            if not horton.cbcred:
                log.info("Cloudbreak instance not found, deploying...")
                init_cbreak_infra()
            else:
                log.info("Cloudbreak instance found for provider, continuing...")


def run_bundle(def_key, rename=None):
    valid_actions = [x for x in dir(actions) if not x.startswith('_')]
    steps = []
    log.info("------------- Running Build")
    if def_key not in horton.defs.keys():
        raise ValueError("def_key {0} not found".format(def_key))
    if 'seq' not in horton.defs[def_key]:
        raise ValueError("Definition [%s] doesn't have a default Sequence",
                         def_key)
    steps += horton.defs[def_key]['seq']
    start_ts = _dt.utcnow()
    log.info("Beginning Deployment at [%s] with step sequence: [%s]",
             start_ts, str(steps))
    for step in steps:
        for action, args in step.items():
            if action in valid_actions:
                # Handle name overrides
                if rename is not None:
                    if action in ['prep_deps', 'prep_spec', 'wait_event']:
                        args[1] = rename
                    elif action in ['write_cache']:
                        args[0] = rename
                    elif action in ['do_builds']:
                        args = [rename]
                log.info("----- Executing Action [%s] with Args [%s] at [%s]",
                         action, str(args), _dt.utcnow())
                getattr(actions, action)(args)
                log.info("----- Completed Action [%s] with Args [%s] at [%s]",
                         action, str(args), _dt.utcnow())
            else:
                log.error("Action %s not valid, skipping", action)
    finish_ts = _dt.utcnow()
    diff_ts = finish_ts - start_ts
    log.info("Completed Deployment Sequence at [%s] after [%d] seconds",
             finish_ts, diff_ts.seconds)


def print_intro():
    init_cbreak_infra(create=False)
    print('\033[1m' + "Welcome to Whoville!" + '\033[0m')
    if horton.cbd:
        cbd_public_ip = horton.cbd.public_ips[0]
        url = 'https://' + cbd_public_ip + '/sl'
        print("\nCloudbreak is available at (browser): " + url)
        print("\nAltus Director is available at (browser): " + url
              .replace('/sl', ':7189'))
        print("Currently Deployed Environments: "
              + 'Cloudbreak: ' + str([x.name for x in deploy.list_stacks()]) + '\n'
              + 'Director: ' + ', '.join(['http://{0}:7180'.format(director.get_deployment(dep_name=x).manager_instance.properties['publicIpAddress']) for x in director.list_deployments()]))
        log.info("Suggested Hosts File Entries for Director Environments:\n{0}"
                 .format('\n'.join(director.get_hostfile_list())))
    if horton.k8svm:
        k8s_master_name = [x for x in horton.k8svm if 'k8s-master' in x][0]
        if isinstance(horton.k8svm[k8s_master_name], list):
            k8s_master_ip = horton.k8svm[k8s_master_name][0].public_ips[0]
        else:
            k8s_master_ip = horton.k8svm[k8s_master_name].public_ips[0]
        print("\nThe K8s Cluster Master is on: " + k8s_master_ip)
    print("\nThe following Definitions are available for Deployment:")
    for def_key in horton.defs.keys():
        print('\033[1m' + "\n  " + def_key + '\033[0m')
        print("        " + horton.defs[def_key].get('desc'))


def user_menu():
    while True:
        print("\nPlease enter a Definition Name to deploy it: ")
        print("e.g.")
        print('\033[1m' + "inf-cda30-single\n" + '\033[0m')
        print("\nAlternately type 'help' to see the Definitions again, 'purge'"
              " to remove all deployed environments from cloudbreak, 'nuke' "
              "to remove everything including Cloudbreak/Director, or 'exit' "
              "to exit gracefully")
        selected = str(input(">> "))
        if selected in ['list', 'help']:
            print_intro()
        elif selected in ['exit', 'quit']:
            print('\033[1m' + "Exiting Whoville!" + '\033[0m')
            exit(0)
        elif selected in ['purge']:
            deploy.purge_cloudbreak(for_reals=True, ns=horton.namespace)
        elif selected in ['nuke']:
            infra.nuke_namespace(dry_run=False)
            exit(0)
        elif selected in horton.defs.keys() or selected.startswith('cdh-'):
            autorun(def_key=selected)
            print("\n    Deployment Completed!\n Menu reload in 5 seconds")
            _sleep(5)
        else:
            print("Sorry, that is not recognised, please try again")


def autorun(def_key, count=1):
    if not horton.defs:
        init_whoville_service()
    if def_key in horton.defs.keys():
        resolve_bundle_reqs(def_key=def_key)
        if count > 1:
            log.info("Multiple deployments (%s) requested", count)
            for x in range(0, count):
                rename = def_key + str(x)
                log.info("Running multiple deployment loop on [%s]", rename)
                run_bundle(def_key=def_key, rename=rename)
        else:
            run_bundle(def_key=def_key)
    else:
        log.info("Definition %s not recognised, please retry", def_key)
    print_intro()


def interactive():
    user_mode = utils.get_val(config.profile, 'user_mode')
    log.info("Name is [%s] running user_menu", __name__)
    init_whoville_service()
    if str(user_mode).lower() == 'ui':
        app.run(host='0.0.0.0', debug=True, port=5000)
    else:
        print_intro()
        user_menu()


@app.route("/api/whoville/v1/getCB")
def getCB():
    if horton.cbd:
        return json.dumps(horton.cbd.public_ips)
    else:
        return Response("", status=404)


@app.route("/api/whoville/v1/")
def apiCheck():
    return "Whoville Rest API is operational..."


@app.route("/api/whoville/v1/getProfile")
def getProfile():
    return json.dumps(config.profile)


@app.route("/api/whoville/v1/getMenu")
def getDefs():
    return json.dumps(horton.defs)


@app.route("/api/whoville/v1/getPackageInfraBreakdown")
def getDefsInfraBreakdown():
    selected = request.args.get('clusterType')
    packageDef = horton.defs[selected]
    specList = [
            x for x in packageDef['seq']
            if 'prep_spec' in x
            ]
    infraList = []
    for x in specList:
        infraList.append({'packageName':x['prep_spec'][0],'instanceName':x['prep_spec'][1]})
    return json.dumps(infraList)


@app.route("/api/whoville/v1/getCredentials")
def getCredentials():
    if horton.cbcred:
        var = {'platform': horton.cbcred.cloud_platform,
               'name': horton.cbcred.name}
        return json.dumps(var)
    else:
        return Response("", status=404)


@app.route("/api/whoville/v1/getStacks")
def getStacks():
    var = json.loads(deploy.list_stacks_json().data.decode())
    return json.dumps(var)


@app.route("/api/whoville/v1/deleteStack")
def deleteStack():
    cluster_id = request.args.get('clusterId')
    var = deploy.delete_stack(stack_id=cluster_id, force=True, wait=False)
    return json.dumps(var)


@app.route("/api/whoville/v1/getTemplates")
def getTemplates():
    var = json.loads(deploy.list_templates_json().data.decode())
    return json.dumps(var)


@app.route("/api/whoville/v1/deployPackage")
def deployPackage():
    selected = request.args.get('clusterType')
    autorun(def_key=selected)
    return 'done'


if __name__ == '__main__':
    interactive()
