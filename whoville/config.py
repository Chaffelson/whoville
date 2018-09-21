# coding: utf-8

"""
A set of defaults and parameters used elsewhere in the project.
Also provides a handy link to the low-level client SDK configuration singleton
objects.
"""

from __future__ import absolute_import
import logging
import os
import urllib3
from whoville.cloudbreak import configuration as cb_config
from whoville import utils


# --- Logging ------
logging.basicConfig(level=logging.INFO)


# --- Default Host URL -----
# Set Default Host for Cloudbreak
cb_config.host = 'https://localhost/cb/api'


# ---  Project Root ------
# Is is helpful to have a reference to the root directory of the project
PROJECT_ROOT_DIR = os.path.abspath(os.path.dirname(__file__))


# --- Task wait delays ------
# Set how fast to recheck for completion of a short running task in seconds
short_retry_delay = 0.5
# Set the max wait time for a short running task to complete in seconds
short_max_wait = 3
# Long running task delay
long_retry_delay = 5
# and long max wait
long_max_wait = 120


# --- Cloudbreak Security
cb_config.verify_ssl = False
if not cb_config.verify_ssl:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Resolve Configuration overrides from local profile
try:
    profile = utils.load(
        utils.fs_read(
            '.profile.yml'
        )
    )
except Exception:
    raise ValueError(".profile.yml not found - Have you set your Profile up?")