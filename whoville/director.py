# -*- coding: utf-8 -*-

"""
For interactions with Cloudera Altus Director

Warnings:
    Experimental, not extensively tested
"""

from __future__ import absolute_import
import logging
from time import sleep
from whoville import config, utils
import cloudera.director.latest as cd
from cloudera.director.common.rest import ApiException

__all__ = ['list_environments', 'get_environment', 'create_environment',
           'delete_environment']

log = logging.getLogger(__name__)
horton = utils.Horton()


def get_environment():
    tgt_env_name = horton.namespace + 'whoville'
    envs = list_environments()
    if tgt_env_name in envs:
        return cd.EnvironmentsApi(horton.cad).get_redacted(tgt_env_name)
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
    if platform['provider'] == 'EC2':
        cad_env = cd.Environment(
            name=horton.namespace + 'whoville',
            credentials=cd.SshCredentials(
                username='ec2-user',
                port=22,
                private_key=utils.fs_read(config.profile['ssh_key_priv'])
            ),
            provider=cd.InstanceProviderConfig(
                type='aws',
                config={
                    'accessKeyId': platform['key'],
                    'secretAccessKey': platform['secret'],
                    'region': platform['region']
                }
            )
        )
    else:
        raise ValueError("Provider not supported")
    try:
        return cd.EnvironmentsApi(horton.cad).create(cad_env)
    except ApiException as e:
        if 'iam:GetInstanceProfile' in e.body:
            sleep(3)
            return cd.EnvironmentsApi(horton.cad).create(cad_env)
        else:
            raise e


def delete_environment(env_name):
    try:
        return cd.EnvironmentsApi(horton.cad).delete(env_name)
    except ApiException as e:
        raise e
