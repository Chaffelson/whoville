#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Convenience utility functions for whoville, not really intended for external use
"""

from __future__ import absolute_import, unicode_literals
import logging
import json
import re
import time
import copy
import base64
import six
from six.moves import reduce
from time import sleep
from datetime import datetime, timedelta
import os
import ruamel.yaml
import requests
from github import Github
from github.GithubException import UnknownObjectException
from requests.models import Response
from whoville import config, security
from pexpect import pxssh
from pexpect.exceptions import EOF
from pexpect.pxssh import ExceptionPxssh

__all__ = ['dump', 'load', 'fs_read', 'fs_write', 'wait_to_complete', 'check_remote_success_file',
           'is_endpoint_up', 'set_endpoint', 'get_val', 'get_remote_shell', 'execute_remote_cmd',
           'load_resources_from_files', 'load_resources_from_github', 'Horton'
           ]

log = logging.getLogger(__name__)
# log.setLevel(logging.DEBUG)


def dump(obj, mode='json'):
    """
    Dumps a native datatype object to json or yaml, defaults to json

    Args:
        obj (varies): The native datatype object to serialise
        mode (str): 'json' or 'yaml', the supported export modes

    Returns (str): The serialised object

    """
    assert mode in ['json', 'yaml']
    try:
        out = json.dumps(
            obj=obj,
            sort_keys=True,
            indent=4
            # default=_json_default
        )
    except TypeError as e:
        raise e
    if mode == 'json':
        return out
    if mode == 'yaml':
        return ruamel.yaml.safe_dump(
            json.loads(out),
            default_flow_style=False
        )
    raise ValueError("Invalid dump Mode specified {0}".format(mode))


def load(obj, dto=None, decode=None):
    """
    Loads a serialised object back into native datatypes, and optionally
    imports it back into the native NiFi DTO

    Warning: Using this on objects not produced by this Package may have
    unintended results! While efforts have been made to ensure that unsafe
    loading is not possible, no stringent security testing has been completed.

    Args:
        obj (dict, list): The serialised object to import
        dto (Optional [tuple{str, str}]): A Tuple describing the service and
        object that should be constructed.

        e.g. dto = ('registry', 'VersionedFlowSnapshot')

    Returns: Either the loaded object in native Python datatypes, or the
        constructed native datatype object

    """
    assert isinstance(obj, (six.string_types, bytes))
    assert dto is None or isinstance(dto, tuple)
    assert decode is None or isinstance(decode, six.string_types)
    # ensure object is standard json before reusing the api_client deserializer
    # safe_load from ruamel.yaml as it doesn't accidentally convert str
    # to unicode in py2. It also manages both json and yaml equally well
    # Good explanation: https://stackoverflow.com/a/16373377/4717963
    # Safe Load also helps prevent code injection
    if decode:
        if decode == 'base64':
            prep_obj = base64.b64decode(obj)
        else:
            raise ValueError("Load's decode option only supports base64")
    else:
        prep_obj = obj
    loaded_obj = ruamel.yaml.safe_load(prep_obj)
    if dto:
        assert dto[0] in ['cloudbreak']
        assert isinstance(dto[1], six.string_types)
        obj_as_json = dump(loaded_obj)
        response = Response()
        response.data = obj_as_json
        api_clients = {
            'cloudbreak': config.cb_config.api_client,
        }
        api_client = api_clients[dto[0]]
        return api_client.deserialize(
            response=response,
            response_type=dto[1]
        )
    return loaded_obj


def fs_write(obj, file_path):
    """
    Convenience function to write an Object to a FilePath

    Args:
        obj (varies): The Object to write out
        file_path (str): The Full path including filename to write to

    Returns: The object that was written
    """
    try:
        with open(str(file_path), 'w') as f:
            f.write(obj)
        return obj
    except TypeError as e:
        raise e


def fs_read(file_path):
    """
    Convenience function to read an Object from a FilePath

    Args:
        file_path (str): The Full path including filename to read from

    Returns: The object that was read
    """
    try:
        with open(str(file_path), 'r') as f:
            return f.read()
    except UnicodeDecodeError:
        with open(str(file_path), 'r', encoding='latin-1') as f:
            return f.read()
    except IOError as e:
        raise e


def wait_to_complete(test_function, *args, **kwargs):
    """
    Implements a basic return loop for a given function which is capable of a
    True|False output

    Args:
        test_function: Function which returns a bool once the target
            state is reached
        delay (int): The number of seconds between each attempt, defaults to
            config.short_retry_delay
        max_wait (int): the maximum number of seconds before issuing a Timeout,
            defaults to config.short_max_wait
        *args: Any args to pass through to the test function
        **kwargs: Any Keyword Args to pass through to the test function

    Returns (bool): True for success, False for not

    """
    log.info("Called wait_to_complete for function %s",
             test_function.__name__)
    delay = kwargs.pop('whoville_delay', config.short_retry_delay)
    max_wait = kwargs.pop('whoville_max_wait', config.short_max_wait)
    timeout = time.time() + max_wait
    while time.time() < timeout:
        log.debug("Calling test_function")
        test_result = test_function(*args, **kwargs)
        log.debug("Checking result")
        if test_result:
            log.debug("Function output [%s] eval to True, returning output",
                     str(test_result)[:25])
            return test_result
        log.debug("Function output [%s] evaluated to False, sleeping...",
                 str(test_result)[:25])
        time.sleep(delay)
    log.debug("Hit Timeout, raising TimeOut Error")
    raise ValueError("Timed Out waiting for {0} to complete".format(
        test_function.__name__))


def is_endpoint_up(endpoint_url, verify=False):
    """
    Tests if a URL is available for requests

    Args:
        endpoint_url (str): The URL to test
        verify (bool): Whether to attempt SSL verification, if SSL needed

    Returns (bool): True for a 200 response, False for not

    """
    log.info("Called is_endpoint_up with args %s", locals())
    try:
        response = requests.get(endpoint_url, verify=verify)
        if response.status_code == 200:
            log.info("Got 200 response from endpoint, returning True")
            return True
        log.info("Got status code %s from endpoint, returning False",
                 response.status_code)
        return False
    except requests.ConnectionError:
        log.info("Got ConnectionError, returning False")
        return False


def get_remote_shell(target_host, sshkey_file=None, user_name=None, wait=True):
    log.info("Getting remote shell for target host [%s]", target_host)
    horton = Horton()
    log.debug("Checking cache for existing Shell session to host")
    shell = horton.shells[target_host] if target_host in horton.shells else None
    if shell:
        if not shell.isalive():
            log.debug("Cached shell is not live, recreating")
            shell = None
        else:
            return shell
    if not shell:
        log.debug("Creating new session")
        sshkey_file = sshkey_file if sshkey_file else config.profile['sshkey_file']
        user_name = user_name if user_name else 'centos'
        while not shell:
            try:
                shell = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
                shell.login(target_host, user_name, ssh_key=sshkey_file, check_local_ip=False)
            except (ExceptionPxssh, EOF):
                if not wait:
                    log.info("Target host is not accepting the connection, Wait is not set, returning False...")
                    return False
                else:
                    log.info("Retrying until target host accepts the connection request...")
                    sleep(5)
            horton.shells[target_host] = shell
            log.info("Returning Shell session...")
    return shell


def execute_remote_cmd(target_host, cmd, expect=None, repeat=False, bool_response=False):
    log.info("Executing remote command [%s] on host [%s] expecting output of [%s] with wait-repeat of [%s] and "
             "bool_response of [%s]", cmd[:100], target_host, str(expect), str(repeat), str(bool_response))
    assert isinstance(cmd, six.string_types)
    assert expect is None or isinstance(expect, six.string_types)
    assert isinstance(repeat, bool)
    assert isinstance(bool_response, bool)
    if bool_response and not expect:
        raise ValueError("Must include an Expect statement with bool_response test")
    s = get_remote_shell(target_host, wait=not bool_response)
    if not s:
        if bool_response:
            log.info("Remote Shell not currently available, bool_respose is set, returning False")
            return False
        else:
            raise ValueError('Remote Shell not available to host [%s]', target_host)
    log.debug("Issuing command [%s]", cmd)
    s.sendline(cmd)
    s.prompt()
    if not expect:
        log.info("Expect not set, returning command result...")
        return s.before.decode()
    while expect not in s.before.decode():
        if bool_response:
            return False
        log.info("Expect set and string not found in response, waiting...")
        sleep(3)
        s.prompt()
        if repeat:
            log.info("Repeat set, reissuing command before checking again")
            s.sendline(cmd)
    log.info("Expect set and found in command response, returning response")
    return s.before.decode()


def check_remote_success_file(target_host, check_file='/tmp/status.success'):

    response = execute_remote_cmd(target_host, 'cat ' + check_file)
    if 'complete' in response:
        log.info("Found complete in .success file, ready to proceed")
        return True
    else:
        log.info("Could not find .success file")
        return False


def set_endpoint(endpoint_url):
    """
    EXPERIMENTAL

    Sets the endpoint when switching between instances of NiFi or other
    projects. Not tested extensively with secured instances.

    Args:
        endpoint_url (str): The URL to set as the endpoint. Autodetects the
        relevant service e.g. 'http://localhost:18080/nifi-registry-api'

    Returns (bool): True for success, False for not
    """
    log.info("Called set_endpoint with args %s", locals())
    if 'cb/api' in endpoint_url:
        log.debug("Setting Cloudbreak endpoint to %s", endpoint_url)
        this_config = config.cb_config
    elif ':7189' in endpoint_url:
        log.debug("Setting Altus Director endpoint to %s", endpoint_url)
        this_config = config.cd_config
    else:
        raise ValueError("Unrecognised API Endpoint")
    try:
        if this_config.api_client:
            log.debug("Found Active API Client, updating...")
            this_config.api_client.host = endpoint_url
    except AttributeError:
        log.debug("No Active API Client found to update")
    this_config.host = endpoint_url
    if this_config.host == endpoint_url:
        return True
    return False


# https://stackoverflow.com/a/36584863/4717963
# https://stackoverflow.com/a/14692747/4717963
def get_val(root, items, sep='.', **kwargs):
    """
    Swagger client objects don't behave like dicts, so need a custom func
    to step down through keys when defined as string vars etc.

    Warnings:
        If you try to retrieve a key that doesn't exist you will get None
        instead of an Attribute Error. Code defensively, or abuse it, whatever.

    Args:
        root [dict, client obj]: The dict or Object to recurse through
        items (list, str): either list or dot notation string of keys to walk
            through
        sep (str): The character expected as a separator when parsing strings

    Returns (varies): The target val at the last key

    """
    assert isinstance(items, (list, six.string_types))
    for key in items if isinstance(items, list) else items.split(sep):
        if root is None:
            return root
        elif isinstance(root, list):
            if '|' not in key:
                raise ValueError("Found list but key {0} does not match list "
                                 "filter format 'x|y'".format(key))
            field, value = key.split('|')
            list_filter = [x for x in root if x.get(field) == value]
            if list_filter:
                root = list_filter[0]
        elif isinstance(root, dict):
            root = root.get(key)
        else:
            root = root.__getattribute__(key)
    return root


def set_val(root, keys, val, sep='.', merge=False, ignore_keys=None,
            squash_keys=None, max_depth=50):
    assert isinstance(keys, (list, six.string_types))
    if isinstance(keys, six.string_types):
        log.debug("got keys as string, splitting using sep [%s]", sep)
        keys = keys.split(sep)
    log.debug("keys are [%s]", str(keys))
    last_key = keys.pop()
    log.debug("grabbing last key [%s] off the end", last_key)
    root = get_val(root, keys, sep)
    log.debug("Got root from keys [%s]", str(keys))
    if not merge:
        log.debug("not merge update, last key is [%s], replacing", last_key)
        root[last_key] = copy.deepcopy(val)
    else:
        log.debug("running merge update on root like [%s] with value like [%s]",
                  str(root)[:100], str(val)[:100])
        merged = deep_merge(
            target=root[last_key], source=copy.deepcopy(val),
            ignore_keys=ignore_keys, squash_keys=squash_keys,
            max_depth=max_depth)
        log.debug("replacing original root at [%s] with merged root like [%s]",
                  last_key, str(merged)[:100])
        root[last_key] = merged


# https://stackoverflow.com/a/18394648/4717963
# This cannot handle nested lists
def deep_merge(target, source, ignore_keys=None, squash_keys=None, depth=0,
               max_depth=50):
    for k, v in source.items():
        if ignore_keys and k in ignore_keys:
            log.debug("k [%s] is on ignore list, skipping", k)
        elif depth == max_depth:
            log.debug("hit max merge depth, squashing k [%s] with new v like "
                      "[%s]", k, str(v)[:100])
            target[k] = v
        elif squash_keys and k in squash_keys:
            log.debug("squashing k [%s] with new v like [%s]", k, str(v)[:100])
            target[k] = v
        elif isinstance(v, dict) and v:
            log.debug("Running recursive update on k [%s]", k)
            target[k] = deep_merge(
                target=target.get(k, {}), source=v, ignore_keys=ignore_keys, 
                squash_keys=squash_keys, depth=depth+1, max_depth=max_depth)
        elif isinstance(v, list):
            log.debug("Merging list under k [%s]", k)
            target[k] = (target.get(k, []) + v)
        else:
            log.debug("simple value, updating [%s] with value like [%s]",
                      k, str(v)[:100])
            target[k] = v
    log.debug("Returning merged object")
    return target


def load_resources_from_github(repo_name, username, token, tgt_dir, ref='master',
                    recurse=True):

    def _recurse_github_dir(g_repo, r_tgt, r_ref):
        contents = g_repo.get_dir_contents(r_tgt, r_ref)
        out = {}
        for obj in contents:
            log.info("loading " + os.sep.join([r_tgt, r_ref, obj.name]))
            if obj.type == 'dir':
                out[obj.name] = _recurse_github_dir(g_repo, obj.path, r_ref)
            elif obj.type == 'file':
                if obj.name.rsplit('.')[1] not in ['yaml', 'json']:
                    out[obj.name] = obj.decoded_content.decode('utf-8')
                else:
                    out[obj.name] = load(obj.decoded_content)
        return out

    try:
        g_accnt = Github(username, token)
    except UnknownObjectException:
        raise ValueError("Github Login failure - please check you have access "
                         "to Repo %s and your token is correctly setup",
                         tgt_dir)
    g_repo = g_accnt.get_repo(repo_name)
    if not recurse:
        listing = g_repo.get_dir_contents(tgt_dir, ref)
        return listing
    return _recurse_github_dir(g_repo, tgt_dir, ref)


def load_resources_from_files(file_path):
    resources = {}
    # http://code.activestate.com/recipes/577879-create-a-nested-dictionary-from-oswalk/
    rootdir = file_path.rstrip(os.sep)
    log.debug("Trying path {0}".format(rootdir))
    head = rootdir.rsplit(os.sep)[-1]
    start = rootdir.rfind(os.sep) + 1
    for path, dirs, files in os.walk(rootdir):
        log.debug("Trying path {0}".format(path))
        folders = path[start:].split(os.sep)
        subdir = dict.fromkeys(files)
        parent = reduce(dict.get, folders[:-1], resources)
        parent[folders[-1]] = subdir
        for file_name in subdir.keys():
            if file_name[0] == '.':
                log.debug("skipping dot file [%s]", file_name)
            else:
                log.debug("loading [%s]", os.path.join(path, file_name))
            if file_name.rsplit('.')[1] not in ['yaml', 'json']:
                subdir[file_name] = fs_read(os.path.join(path, file_name))
            else:
                # Valid yaml can't have tabs, only spaces
                # proactively replacing tabs as some tools do it wrong
                subdir[file_name] = load(
                    fs_read(os.path.join(
                        path, file_name
                    ))
                )
    return resources[head]


def singleton(cls, *args, **kw):
    instances = {}

    def _singleton():
        if cls not in instances:
            instances[cls] = cls(*args, **kw)
        return instances[cls]
    return _singleton


@singleton
class Horton:
    """
    Borg Singleton to share state between the various processes.
    Looks complicated, but it makes the rest of the code more readable for
    Non-Python natives.
    ...
    Why Horton? Because an Elephant Never Forgets
    """
    def __init__(self):
        self.cbd = None  # Server details for orchestration host
        self.cbcred = None  # Credential for deployments, once loaded in CB
        self.cdcred = None  # Credential for deployments, once loaded in CD
        self.cad = None  # Client for Altus Director, once created
        self.k8svm = {}  # Reference for K8s environment, once created
        self.resources = {}  # all loaded resources from github/files
        self.defs = {}  # deployment definitions, once pulled from resources
        self.specs = {}  # stack specifications, once formulated
        self.stacks = {}  # stacks deployed, once submitted
        self.deps = {}  # Dependencies loaded for a given Definition
        self.seq = {}  # Prioritised list of tasks to execute
        self.cache = {}  # Key:Value store for passing params between Defs
        self.shells = {}  # Key:Value session store for remote shells
        self.namespace = config.profile['namespace']
        self.global_purge = config.profile['globalpurge'] if 'globalpurge' in config.profile else False

    def __iter__(self):
        for attr, value in self.__dict__.items():
            yield attr, value

    def _getr(self, keys, sep=':', **kwargs):
        """
        Convenience function to retrieve params in a very readable method

        Args:
            keys (str): dot notation string of the key for the value to be
                retrieved. e.g 'secret.cloudbreak.hostname'

        Returns:
            The value if found, or None if not
        """
        return get_val(self, keys, sep, **kwargs)

    def _setr(self, keys, val, sep=':', **kwargs):
        set_val(self, keys, val, sep, **kwargs)


def validate_profile():
    log.info("Validating provided profile.yml")
    horton = Horton()
    # TODO: Check VPN if OpenStack
    # Check Profile is imported
    if not config.profile:
        raise ValueError("whoville Config Profile is not populated with"
                         "deployment controls, cannot proceed")
    # Check Profile version
    if 'profilever' not in config.profile:
        raise ValueError("Your Profile is out of date, please recreate your "
                         "Profile from the template")
    if config.profile['profilever'] < config.min_profile_ver:
        raise ValueError("Your Profile is out of date, please recreate your "
                         "Profile from the template. Profile v3 requires an ssh private key or pem file.")
    # Handle SSH
    if 'sshkey_file' in config.profile and config.profile['sshkey_file']:
        assert config.profile['sshkey_file'].endswith('.pem')
        from Crypto.PublicKey import RSA
        pem_key = RSA.importKey(fs_read(config.profile['sshkey_file']))
        config.profile['sshkey_pub'] = pem_key.publickey().exportKey(format="OpenSSH").decode()
        config.profile['sshkey_priv'] = pem_key.exportKey().decode()
        config.profile['sshkey_name'] = os.path.basename(config.profile['sshkey_file']).split('.')[0]
    else:
        assert any(k in config.profile for k in ['ssh_key_priv', 'sshkey_priv'])
        assert all(k in config.profile for k in ['sshkey_pub', 'sshkey_name'])
    # Check Namespace
    assert isinstance(horton.namespace, six.string_types),\
        "Namespace must be string"
    assert len(horton.namespace) >= 2,\
        "Namespace must be at least 2 characters"
    # Check Password
    if 'password' in config.profile and config.profile['password']:
        horton.cache['ADMINPASSWORD'] = config.profile['password']
    else:
        horton.cache['ADMINPASSWORD'] = security.get_secret('ADMINPASSWORD')
    password_test = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d-]{12,}$')
    if not bool(password_test.match(horton.cache['ADMINPASSWORD'])):
        raise ValueError("Password doesn't match Platform spec."
                         "Requires 12+ characters, at least 1 letter and "
                         "number, may also contain -")
    # Check Provider
    platform = config.profile.get('platform')
    assert platform['provider'] in ['EC2', 'AZURE_ARM', 'GCE', 'OPENSTACK']
    if platform['provider'] == 'GCE':
        if 'apikeypath' in platform:
            with open(platform['apikeypath'], "r") as apikey:
                platform['jsonkey'] = apikey.read()
    # TODO: Read in the profile template, check it has all matching keys
    # Check Profile Namespace is valid
    ns_test = re.compile(r'[a-z0-9-]')
    if not bool(ns_test.match(horton.namespace)):
        raise ValueError("Namespace must only contain 0-9 a-z -")
    # Check storage bucket matches expected format
    if 'bucket' in config.profile:
        if platform['provider'] == 'EC2':
            bucket_test = re.compile(r'[a-z0-9.-]')
        elif platform['provider'] == 'AZURE_ARM':
            bucket_test = re.compile(r'[a-z0-9@]')
        elif platform['provider'] == 'GCE':
            bucket_test = re.compile(r'[a-z0-9.-]')
        else:
            raise ValueError("bucket listed in Profile but Platform Provider not supported")
        if not bool(bucket_test.match(config.profile['bucket'])):
            raise ValueError("Bucket name doesn't match Platform spec")
    # check tags
    if 'tags' not in config.profile:
        raise ValueError("Profile is missing mandatory tags entries")
    tags = config.profile['tags']
    for tag in ['owner']:
        assert tag in tags, "tag {0} missing from profile".format(tag)
        assert isinstance(tag, six.string_types) and len(tag) > 3, "Tag {0} must be a string over 3 chars".format(tag)


def resolve_tags(instance_name, owner):
    tags = config.profile.get('tags')
    if tags is not None:
        if 'owner' not in tags or tags['owner'] is None:
            tags['owner'] = owner
        if 'startdate' not in tags or tags['startdate'] is None:
            tags['startdate'] = str(datetime.now().strftime("%m%d%Y").lower())
        if 'enddate' not in tags or tags['enddate'] is None:
            tags['enddate'] = str(
                (datetime.now() + timedelta(days=2)).strftime("%m%d%Y").lower())
        if 'project' not in tags or tags['project'] is None:
            tags['project'] = 'selfdevelopment'
        if 'deploytool' not in tags or tags['deploytool'] is None:
            tags['deploytool'] = 'whoville'
        tags['dps'] = 'false'
        tags['datalake'] = 'false'
    else:
        tags = {'datalake': 'false', 'dps': 'false'}

    if 'dps' in instance_name:
        tags['dps'] = 'true'
    if 'datalake' in instance_name:
        tags['datalake'] = 'true'
    return tags
