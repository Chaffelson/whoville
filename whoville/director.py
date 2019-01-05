# -*- coding: utf-8 -*-

"""
For interactions with Cloudera Altus Director

Warnings:
    Experimental, not extensively tested
"""

from __future__ import absolute_import
import logging
import cloudera.director.latest as cd
from whoville.deploy import Horton
from cloudera.director.common.rest import ApiException

__all__ = ['list_environments']

log = logging.getLogger(__name__)
horton = Horton()


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
