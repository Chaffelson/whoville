# -*- coding: utf-8 -*-

"""
Secure connectivity management
"""

from __future__ import absolute_import
import logging
import six
import requests
import secrets
import string
from six.moves.urllib import parse
from whoville import config


log = logging.getLogger(__name__)

__all__ = ['service_login', 'set_service_auth_token']

# These are the services that these functions know how to configure
_valid_services = ['cloudbreak']


def service_login(service='cloudbreak', username=None, password=None,
                  bool_response=False):
    """
    Login to the currently configured server.

    Login requires a secure connection over https.
    Prior to calling this method, the host must be specified
    and the SSLContext should be configured (if necessary).

    Successful login will result in a generated token (JWT) being
    cached in the api_client config that will be passed in all future
    REST API calls. To clear that token, call service_logout.

    The token is temporary and will expire after a duration set by
    the server. After a token expires, you must call
    this method again to generate a new token.

    Args:
        service (str): 'cloudbreak'; the service to login to
        username (str): The username to submit
        password (str): The password to use
        bool_response (bool): If True, the function will return False instead
            of an error. Useful for connection testing.

    Returns:
        (bool): True if successful, False or an Error if not. See bool_response

    """
    log_args = locals()
    _ = log_args.pop('password')
    log.info("Called service_login with args %s", log_args)
    assert service in _valid_services
    assert isinstance(username, six.string_types)
    assert isinstance(password, six.string_types)
    assert isinstance(bool_response, bool)

    if service == 'cloudbreak':
        configuration = config.cb_config
    else:
        raise ValueError("Unrecognised Service parameter")

    assert configuration.host, "Host must be set prior to logging in."
    assert configuration.host.startswith("https"), \
        "Login is only available when connecting over HTTPS."

    if service == 'cloudbreak':
        url = config.cb_config.host.replace(
            '/cb/api',
            '/identity/oauth/authorize'
        )
        redirect_uri = config.cb_config.host.replace(
            '/cb/api',
            '/authorize'
        )
        resp = requests.post(
            url=url,
            params={
                'response_type': 'token',
                'client_id': 'cloudbreak_shell',
                'scope.0': 'openid',
                'source': 'login',
                'redirect_uri': 'http://cloudbreak.shell'
            },
            headers={
                'accept': 'application/x-www-form-urlencoded'
            },
            verify=config.cb_config.verify_ssl,
            allow_redirects=False,
            data=[
                ('credentials',
                 '{"username":"' + username + '",'
                 '"password":"' + password + '"}'),
            ]
        )
        try:
            token = parse.parse_qs(resp.headers['Location'])['access_token'][0]
            # Todo: get the expiry and set into config as well
            # Todo: use expiry to refresh the token as required
            # Todo: Find approach to auto fetch the token as required
        except KeyError:
            if bool_response:
                return False
            raise ConnectionError("No Access Token in server response. Please "
                                  "check your Auth config and environment.")
        set_service_auth_token(token=token, service='cloudbreak')
        return True


def set_service_auth_token(token=None, token_name='tokenAuth', service='cloudbreak'):
    """
    Helper method to set the auth token correctly for the specified service

    Args:
        token (Optional[str]): The token to set. Defaults to None.
        token_name (str): the api_key field name to set the token to. Defaults
            to 'tokenAuth'
        service (str): 'nifi' or 'registry', the service to set

    Returns:
        (bool): True on success, False if token not set
    """
    assert service in _valid_services
    assert isinstance(token_name, six.string_types)
    assert token is None or isinstance(token, six.string_types)
    if service == 'cloudbreak':
        configuration = config.cb_config
    else:
        raise ValueError("Unrecognised Service Name")
    configuration.api_key[token_name] = token
    configuration.api_key_prefix[token_name] = 'Bearer'
    if not configuration.api_key[token_name]:
        return False
    return True


def generate_passphrase(length=4):
    try:
        with open('/usr/share/dict/words') as f:
            words = [word.strip() for word in f]
            return '-'.join(secrets.choice(words) for i in range(length))
    except FileNotFoundError:
        return generate_password(length=length*5)


def generate_password(length=20):
    pick_list = string.ascii_letters + string.digits
    return ''.join(secrets.choice(pick_list) for i in range(length))


def get_secret(key='password', create=True):
    assert key in ['password', 'masterkey']
    secret = config.profile.get(key)
    if not secret:
        if create:
            secret = generate_passphrase()
            config.profile[key] = secret
        else:
            return None
    return secret