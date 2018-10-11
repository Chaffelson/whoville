# -*- coding: utf-8 -*-

"""
Populates a provided Cloudbreak Instance with resources for Demos

Warnings:
    Experimental
"""

from __future__ import absolute_import as _abs_imp
import logging
import socket as _socket
from time import sleep as _sleep
from datetime import datetime as _dt
from whoville import config, utils, security, infra, deploy, actions


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


# 'horton' is a shared state function to make deployment more readable
# to non-python users
horton = deploy.Horton()


def step_1_init_service():
    init_start_ts = _dt.utcnow()
    log.info("------------- Initialising Whoville Deployment Service at [%s]",
             init_start_ts)
    log.info("------------- Validating Profile")
    if not config.profile:
        raise ValueError("whoville Config Profile is not populated with"
                         "deployment controls, cannot proceed")
    log.info("------------- Loading Default Resources")
    horton.resources.update(
        utils.load_resources_from_files('/Users/vvaks/git/whoville/resources/v2')
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
    for k, v in horton.resources.items():
        horton.defs[k] = v[k + '.yaml']
    init_finish_ts = _dt.utcnow()
    diff_ts = init_finish_ts - init_start_ts
    log.info("Completed Service Init at [%s] after [%d] seconds",
             init_finish_ts, diff_ts.seconds)


def step_2_init_infra(create_wait=0):
    init_start_ts = _dt.utcnow()
    log.info("------------- Getting Cloudbreak Environment at [%s]",
             init_start_ts)
    horton.cbd = infra.get_cloudbreak(
        purge=horton.global_purge,
        create_wait=create_wait
    )
    log.info("------------- Connecting to Cloudbreak")
    cbd_public_ip = horton.cbd.public_ips[0]
    #public_dns_name = str(_socket.gethostbyaddr(cbd_public_ip)[0])
    #url = 'https://' + public_dns_name + '/cb/api'
    url = 'https://' + cbd_public_ip + '/cb/api'
    log.info("Setting endpoint to %s", url)
    utils.set_endpoint(url)
    log.info("------------- Authenticating to Cloudbreak")
    auth_success = security.service_login(
            service='cloudbreak',
            username=config.profile['email'],
            password=config.profile['password'],
            bool_response=False
        )
    if not auth_success:
        raise ConnectionError("Couldn't login to Cloudbreak")
    else:
        log.info('Logged into Cloudbreak at [%s]', url)
    # Cloudbreak may have just booted and not be ready for queries yet
    # Waiting up to an additional minute for query success
    log.info("Waiting for Cloudbreak API Calls to be available")
    utils.wait_to_complete(
        deploy.list_blueprints,
        bool_response=True,
        whoville_delay=5,
        whoville_max_wait=120
    )
    log.info("------------- Setting Deployment Credential")
    horton.cred = deploy.get_credential(
        config.profile['namespace'] + 'credential',
        create=True,
        purge=horton.global_purge
    )
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
    finish_ts = _dt.utcnow()
    diff_ts = finish_ts - start_ts
    log.info("Completed Deployment Sequence at [%s] after [%d] seconds",
             finish_ts, diff_ts.seconds)


def print_intro():
    #public_dns_name = str(_socket.gethostbyaddr(horton._getr('cbd:public_ips')[0])[0])     
    #url = 'https://' + public_dns_name + '/sl'
    print("")
    cbd_public_ip = horton.cbd.public_ips[0]
    url = 'https://' + cbd_public_ip + '/sl'
    print('\033[1m' + "Welcome to Whoville!" + '\033[0m')
    print("\nCloudbreak is available at (browser): " + url)
    print("Currently Deployed Stacks: " + str(
        [x.name for x in deploy.list_stacks()])
          )
    print("\nThe following Definitions are available for Deployment to "
          "Cloudbreak:")
    for def_key in horton.defs.keys():
        print('\033[1m' + "\n  " + def_key + '\033[0m')
        print("        " + horton.defs[def_key].get('desc'))
    print("\nPlease enter a Definition Name to deploy it: ")
    print("e.g.")
    print('\033[1m' + "  inf-cda30-single\n" + '\033[0m')


def user_menu():
    while True:
        print("\nPlease enter a Definition Name to deploy it: ")
        print("e.g.")
        print('\033[1m' + "  inf-cda30-single\n" + '\033[0m')
        print("\nAlternately type 'help' to see the Definitions again, or "
              "'exit' to exit gracefully")
        selected = str(input(">> "))
        if selected in ['list', 'help']:
            print_intro()
        elif selected in ['exit', 'quit']:
            print('\033[1m' + "Exiting Whoville!" + '\033[0m')
            exit(0)
        elif selected in horton.defs.keys():
            autorun(def_key=selected)
            print("\n    Deployment Completed!\n Menu reload in {0} seconds"
                  .format(create_wait))
            _sleep(create_wait)
        else:
            print("Sorry, that is not recognised, please try again")


def autorun(def_key=None):
    # Check output of last step of staging process
    if not horton.defs:
        step_1_init_service()
    if not horton.cred:
        step_2_init_infra()
    step_3_sequencing(def_key=def_key)
    step_4_build()


if __name__ == '__main__':
    log.info("Name is [%s] running user_menu", __name__)
    create_wait = 5
    step_1_init_service()
    step_2_init_infra(create_wait=create_wait)
    print_intro()
    user_menu()