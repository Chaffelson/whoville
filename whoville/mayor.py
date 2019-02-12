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

import whoville.utils
from whoville import config, utils, security, infra, deploy, actions, director
from flask import Flask
from flask import request

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


# 'horton' is a shared state function to make deployment more readable
# to non-python users
horton = utils.Horton()
app = Flask(__name__)


def step_1_init_service():
    init_start_ts = _dt.utcnow()
    log.info("------------- Initialising Whoville Deployment Service at [%s]",
             init_start_ts)
    log.info("------------- Validating Profile")
    whoville.utils.validate_profile()
    log.info("------------- Loading Default Resources")
    default_resources = os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'resources', 'v2'
    ))
    horton.resources.update(
        utils.load_resources_from_files(default_resources)
    )
    log.info("------------- Fetching Resources from Profile Definitions")
    if config.profile['resources']:
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
        log.warning("Found no additional Resources to load!")
    key_test = _re.compile(r'[a-z0-9-.]')
    for def_key, res_list in horton.resources.items():
        for res_filename, res_content in res_list.items():
            if not bool(key_test.match(res_filename)):
                raise ValueError("Resource Name must only contain 0-9 a-z - .")
        horton.defs[def_key] = res_list[def_key + '.yaml']
    init_finish_ts = _dt.utcnow()
    diff_ts = init_finish_ts - init_start_ts
    log.info("Completed Service Init at [%s] after [%d] seconds",
             init_finish_ts, diff_ts.seconds)


def step_2_init_infra(create_wait=0):
    init_start_ts = _dt.utcnow()
    log.info("------------- Getting Environment at [%s]",
             init_start_ts)
    horton.cbd = infra.get_cloudbreak(
        purge=horton.global_purge,
        create_wait=create_wait
    )
    log.info("------------- Connecting to Environment")
    public_ip = horton.cbd.public_ips[0]
    cbd_url = 'https://' + public_ip + '/cb/api'
    cad_url = 'https://' + public_ip + ':7189'
    log.info("Setting Cloudbreak endpoint to %s", cbd_url)
    utils.set_endpoint(cbd_url)
    log.info("Setting Altus Director endpoint to %s", cad_url)
    utils.set_endpoint(cad_url)
    log.info("------------- Authenticating to Cloudbreak")
    cbd_auth_success = security.service_login(
            service='cloudbreak',
            username=config.profile['email'],
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
        username=config.profile['username'],
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
    # # Director may not be ready for queries yet
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
    horton.cadcred = director.get_environment()
    init_finish_ts = _dt.utcnow()
    diff_ts = init_finish_ts - init_start_ts
    log.info("Completed Infrastructure Init at [%s] after [%d] seconds",
             init_finish_ts, diff_ts.seconds)


def step_3_sequencing(def_key=None):
    log.info("------------- Establishing Deployment Sequence")
    if def_key:
        if def_key not in horton.defs.keys():
            raise ValueError("def_key {0} not found".format(def_key))
        horton.seq[1] = horton._getr(
            'defs:' + def_key + ':seq'
        )
    else:
        for def_key in horton.defs.keys():
            log.info("Checking Definition [%s]", def_key)
            priority = horton._getr('defs:' + def_key + ':priority')
            if priority is not None:
                log.info("Registering [%s] as Priority [%s]",
                         def_key, str(priority))
                horton.seq[priority] = horton._getr(
                    'defs:' + def_key + ':seq'
                )
            else:
                log.info("Priority not set for [%s], skipping...", def_key)


def step_4_build(def_key=None):
    valid_actions = [x for x in dir(actions) if not x.startswith('_')]
    steps = []
    log.info("------------- Running Build")
    if not def_key:
        for seq_key in sorted(horton.seq.keys()):
            log.info("Loading steps for Sequence Priority [%s]", str(seq_key))
            steps += horton.seq[seq_key]
    else:
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
    cbd_public_ip = horton.cbd.public_ips[0]
    url = 'https://' + cbd_public_ip + '/sl'
    print('\033[1m' + "Welcome to Whoville!" + '\033[0m')
    print("\nCloudbreak is available at (browser): " + url)
    print("\nAltus Director is available at (browser): " + url
          .replace('/sl', ':7189'))
    print("Currently Deployed Environments: " + str(
        [x.name for x in deploy.list_stacks()])
          )
    print("\nThe following Definitions are available for Deployment to "
          "Cloudbreak:")
    for def_key in horton.defs.keys():
        print('\033[1m' + "\n  " + def_key + '\033[0m')
        print("        " + horton.defs[def_key].get('desc'))
    print("\nTo deploy a CDH cluster, type 'cdh-' followed by the version "
          "number, e.g. 'cdh-5.12.2'")


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


def autorun(def_key=None):
    # Check output of last step of staging process
    if not horton.defs:
        step_1_init_service()
    if not horton.cbcred:
        step_2_init_infra()
    if def_key in horton.defs.keys():
        step_3_sequencing(def_key=def_key)
        step_4_build()
    elif 'cdh-' in def_key:
        director.chain_deploy(cdh_ver=def_key.split('-')[-1])
    else:
        log.info("Definition %s not recognised, please retry", def_key)
    print_intro()


@app.route("/api/whoville/v1/getCB")
def getCB():
    return json.dumps(horton.cbd.public_ips)


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
    var = {'platform': horton.cbcred.cloud_platform,
           'name': horton.cbcred.name}
    return json.dumps(var)


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
    user_mode = utils.get_val(config.profile, 'user_mode')
    log.info("Name is [%s] running user_menu", __name__)
    step_1_init_service()
    step_2_init_infra(create_wait=5)

    if user_mode:
        app.run(host='0.0.0.0', debug=True, port=5000)
    else:
        print_intro()
        user_menu()
