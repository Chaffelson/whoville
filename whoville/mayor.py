# -*- coding: utf-8 -*-

"""
Populates a provided Cloudbreak Instance with resources for Demos

Warnings:
    Experimental
"""

from __future__ import absolute_import
import logging
import socket
from datetime import datetime
from whoville import config, utils, security, infra, deploy


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


# 'horton' is a shared state function to make deployment more readable
# to non-python users
horton = deploy.Horton()

def step_1_init_service():
    log.info("------------- Initialising Whoville Deployment Service")
    log.info("------------- Validating Profile")
    if not config.profile:
        raise ValueError("whoville Config Profile is not populated with"
                         "deployment controls, cannot proceed")
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
        for k, v in horton.resources.items():
            horton.defs[k] = v[k + '.yaml']
    else:
        log.warning("Found no Resources to load!")


def step_2_init_infra():
    log.info("------------- Getting Cloudbreak Environment")
    horton.cbd = infra.get_cloudbreak(
        purge=horton.global_purge
    )
    log.info("------------- Connecting to Cloudbreak")
    public_dns_name = str(
        socket.gethostbyaddr(horton.find('cbd:public_ips')[0])[0]
    )
    url = 'https://' + public_dns_name + '/cb/api'
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
        whoville_max_wait=60
    )
    log.info("------------- Setting Deployment Credential")
    horton.cred = deploy.get_credential(
        config.profile['namespace'] + 'credential',
        create=True,
        purge=horton.global_purge
    )


def step_3_sequencing(def_key=None):
    log.info("------------- Establishing Deployment Sequence")
    if def_key:
        horton.seq[1] = horton.find(
            'defs:' + def_key + ':seq'
        )
    else:
        for def_key in horton.defs.keys():
            log.info("Checking Definition [%s]", def_key)
            priority = horton.find('defs:' + def_key + ':priority')
            if priority is not None:
                log.info("Registering [%s] as Priority [%s]",
                         def_key, str(priority))
                horton.seq[priority] = horton.find(
                    'defs:' + def_key + ':seq'
                )
            else:
                log.info("Priority not set for [%s], skipping...", def_key)


def step_4_build():
    for seq_key in sorted(horton.seq.keys()):
        log.info("Running Deployment Priority [%s]", str(seq_key))
        start_ts = datetime.utcnow()
        log.info("Started Priority [%s] at [%s]", str(seq_key), start_ts)
        steps = horton.seq[seq_key]
        for step in steps:
            step_ts = datetime.utcnow()
            for action, args in step.items():
                log.info("Executing Action [%s] with Args [%s] at [%s]",
                         action, str(args), datetime.utcnow())
                if action == 'prepdeps':
                    def_key = args[0]
                    shortname = args[1]
                    deploy.prep_dependencies(def_key, shortname)
                if action == 'prepspec':
                    def_key = args[0]
                    shortname = args[1]
                    deploy.prep_stack_specs(def_key, shortname)
                if action == 'deploy':
                    for spec_key in args:
                        fullname = horton.namespace + spec_key
                        deploy.create_stack(
                            fullname,
                            purge=False
                        )
                if action == 'wait':
                    def_key = args[0]
                    spec_key = args[1]
                    fullname = horton.namespace + spec_key
                    field = args[2]
                    state = args[3]
                    deploy.wait_for_event(
                        fullname,
                        field,
                        state,
                        step_ts,
                        horton.defs[def_key]['deploywait']
                    )
                if action == 'openport':
                    protocol = args[0]
                    start_port = args[1]
                    end_port = args[2]
                    cidr = args[3]
                    deploy.add_security_rule(
                        protocol=protocol,
                        start=start_port,
                        end=end_port,
                        cidr=cidr
                    )
                if action == 'writecache':
                    spec_key = args[0]
                    fullname = horton.namespace + spec_key
                    target = args[1]
                    cache_key = args[2]
                    deploy.write_cache(fullname, target, cache_key)
                if action == 'replace':
                    def_key = args[0]
                    res_name = args[1]
                    cache_key = args[2]
                    log.info("Replacing string [%s] with [%s] in Resource [%s]"
                             " in def [%s]",
                             cache_key, horton.cache[cache_key], res_name,
                             def_key)
                    s = horton.resources[def_key][res_name].replace(
                        cache_key, horton.cache[cache_key]
                    )
                    horton.resources[def_key][res_name] = s
                log.info("Completed Action [%s] with Args [%s] at [%s]",
                         action, str(args), datetime.utcnow())
        finish_ts = datetime.utcnow()
        diff_ts = finish_ts - start_ts
        log.info("Completed Deployment [%s] at [%s] after [%d] seconds",
                 seq_key, finish_ts, diff_ts.seconds)


def autorun(def_key=None):
    step_1_init_service()
    step_2_init_infra()
    step_3_sequencing(def_key)
    step_4_build()


if __name__ == '__main__':
    autorun()
    exit(0)
