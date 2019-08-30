# -*- coding: utf-8 -*-

"""
Action Primitives for Deployment Orchestration.
Used by Mayor to resolve deployment sequences

Warnings:
    Experimental
"""

from __future__ import absolute_import as _absolute_import
import logging as _logging
import copy
from datetime import datetime as _datetime
from whoville import deploy, utils, director
from whoville import cloudbreak as _cb

_horton = utils.Horton()

log = _logging.getLogger(__name__)


def prep_deps(args):
    def_key = args[0]
    shortname = args[1]
    deploy.prep_dependencies(def_key, shortname)


def prep_spec(args):
    def_key = args[0]
    shortname = args[1]
    if 'orchestrator' not in _horton.defs[def_key]:
        # Default to Cloudbreak deploy
        deploy.prep_stack_specs(def_key, shortname)
    elif 'director' in _horton.defs[def_key]['orchestrator']:
        fullname = _horton.namespace + shortname
        scripts = copy.deepcopy(_horton.resources[def_key])
        _ = scripts.pop(def_key + '.yaml')
        _horton.specs[fullname] = {
            'cm_ver': str(_horton.defs[def_key]['cmver']),
            'tls_start': _horton.defs[def_key]['tls_start'],
            'csds': _horton.defs[def_key]['csds'] if 'csds' in _horton.defs[def_key] else None,
            'clusters': _horton.defs[def_key]['clusters'],
            'scripts': scripts
        }
    else:
        raise ValueError("Orchestrator not supported")


def do_builds(args):
    for spec_key in args:
        fullname = _horton.namespace + spec_key
        if isinstance(_horton.specs[fullname], _cb.StackV2Request):  # Cloudbreak only Type
            deploy.create_stack(
                fullname,
                purge=False
            )
            deploy.wait_for_event(
                fullname,
                'event_type',
                'BILLING_STARTED',
                _datetime.utcnow(),
                600
            )
        elif 'cm_ver' in _horton.specs[fullname]:
            # Using Director
            director.chain_deploy(
                cm_ver=str(_horton.specs[fullname]['cm_ver']),
                dep_name=fullname,
                clusters=_horton.specs[fullname]['clusters'],
                tls_start=_horton.specs[fullname]['tls_start'],
                csds=_horton.specs[fullname]['csds'],
                scripts=_horton.specs[fullname]['scripts']
            )
        else:
            raise ValueError("Orchestrator not supported")


def wait_event(args):
    def_key = args[0]
    spec_key = args[1]
    fullname = _horton.namespace + spec_key
    field = args[2]
    state = args[3]
    deploy.wait_for_event(
        fullname,
        field,
        state,
        _datetime.utcnow(),
        _horton.defs[def_key]['deploywait']
    )


def open_port(args):
    protocol = args[0]
    start_port = args[1]
    end_port = args[2]
    cidr = args[3]
    if 'CDSWIP' in cidr:
        cidr = _horton.cache['CDSWIP'] + '/32'
    deploy.add_security_rule(
        protocol=protocol,
        start=start_port,
        end=end_port,
        cidr=cidr,
        description='FromDemoSeq'
    )


def write_cache(args):
    spec_key = args[0]
    fullname = _horton.namespace + spec_key
    target = args[1]
    cache_key = args[2]
    deploy.write_cache(fullname, target, cache_key)


def upload_recipe_to_k8s(args):
    target_host_name = [x for x in _horton.k8svm if 'master' in x][0]
    if isinstance(_horton.k8svm[target_host_name], list):
        target_host_ip = _horton.k8svm[target_host_name][0].public_ips[0]
    else:
        target_host_ip = _horton.k8svm[target_host_name].public_ips[0]    
    payload = _horton.resources[args[0]][args[1]]
    cmd = 'tee /tmp/' + args[1] + ' <<-\'END\'\n' + payload + '\nEND'
    utils.execute_remote_cmd(target_host_ip, cmd, expect=None,
                             repeat=False, bool_response=False)
    cmd = 'chmod 755 /tmp/' + args[1]
    utils.execute_remote_cmd(target_host_ip, cmd, expect=None,
                             repeat=False, bool_response=False)


def exec_recipe_on_k8s(args):
    target_host_name = [x for x in _horton.k8svm if 'master' in x][0]
    if isinstance(_horton.k8svm[target_host_name], list):
        target_host_ip = _horton.k8svm[target_host_name][0].public_ips[0]
    else:
        target_host_ip = _horton.k8svm[target_host_name].public_ips[0]
    cmd = 'sudo /tmp/' + args[1] + ' > /tmp/whoville.recipe.log 2>&1'
    utils.execute_remote_cmd(target_host_ip, cmd, expect=None,
                             repeat=False, bool_response=False)


def replace_str(args):
    def_key = args[0]
    res_name = args[1]
    cache_key = args[2]
    resource = _horton.resources[def_key][res_name]
    # Read
    if isinstance(resource, dict):
        source = utils.dump(resource)
    else:
        source = resource
    # Replace String
    if cache_key in _horton.cache:
        log.info(
            "Replacing string [%s] with [%s] in Resource [%s] in def [%s]",
            cache_key, _horton.cache[cache_key], res_name, def_key)
        target = source.replace(cache_key, _horton.cache[cache_key])
    else:
        if '|' in cache_key:
            old, new = cache_key.split('|')
            log.info("Substitution format found in replace value, replacing "
                     "[%s] with [%s] in resource [%s] in def [%s]",
                     old, new, res_name, def_key)
            target = source.replace(old, new)
        else:
            raise ValueError("Replacement value not in Cache or bad format")
    # Write
    if isinstance(resource, dict):
        _horton.resources[def_key][res_name] = utils.load(target)
    else:
        _horton.resources[def_key][res_name] = target


def copy_def(args):
    sep = args[2] if len(args) > 2 else ':'
    s = args[0]
    t = args[1]
    for d in ['defs', 'resources']:
        log.info("-- Running copy_def on [%s] component", d)
        _horton._setr(
            sep.join([d, t]),
            _horton._getr(sep.join([d, s]), sep=sep),
            sep=sep,
            merge=False
        )
    s_def = args[0] + '.yaml'
    t_def = args[1] + '.yaml'
    log.info("Copying definition from def %s resource %s to def %s resource %s",
             s, s_def, t, t_def)
    _horton.resources[t][t_def] = copy.deepcopy(_horton.resources[s][s_def])


def merge_def(args):
    sep = args[2] if len(args) > 2 else ':'
    s = args[0]
    t = args[1]
    source = sep.join(['defs', s])
    target = sep.join(['defs', t])
    log.info("-- Running merge_def on defs")
    _horton._setr(
        target,
        _horton._getr(source, sep=sep),
        sep=sep,
        merge=True,
        squash_keys=['seq']
    )
    source = sep.join(['resources', s])
    target = sep.join(['resources', t])
    log.info("-- Running merge_def on resources")
    _horton._setr(
        target,
        _horton._getr(source, sep=sep),
        sep=sep,
        merge=True,
        max_depth=1
    )


def call_seq(args):
    from whoville.mayor import run_bundle
    def_key_to_build = args[0]
    run_bundle(def_key_to_build)
