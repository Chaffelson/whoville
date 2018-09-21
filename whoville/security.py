# -*- coding: utf-8 -*-

"""
Secure connectivity management
"""

from __future__ import absolute_import
import logging
import six
import requests
from six.moves.urllib import parse
import urllib3
import whoville


log = logging.getLogger(__name__)

__all__ = ['service_login', 'set_service_auth_token',
           'service_logout', 'get_service_access_status']

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
    log_args['password'] = 'REDACTED'
    log.info("Called service_login with args %s", log_args)
    # TODO: Tidy up logging and automate sensitive value redaction
    assert service in _valid_services
    assert isinstance(username, six.string_types)
    assert isinstance(password, six.string_types)
    assert isinstance(bool_response, bool)

    if service == 'cloudbreak':
        configuration = whoville.config.cb_config
    else:
        raise ValueError("Unrecognised Service parameter")

    assert configuration.host, "Host must be set prior to logging in."
    assert configuration.host.startswith("https"), \
        "Login is only available when connecting over HTTPS."

    if service == 'cloudbreak':
        # TOdo: add tests for cloubreak auth
        url = whoville.config.cb_config.host.replace(
            '/cb/api',
            '/identity/oauth/authorize'
        )
        redirect_uri = whoville.config.cb_config.host.replace(
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
            verify=whoville.config.cb_config.verify_ssl,
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
                                  "check your config and environment.")
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
        configuration = whoville.config.cb_config
    else:
        raise ValueError("Unrecognised Service Name")
    configuration.api_key[token_name] = token
    configuration.api_key_prefix[token_name] = 'Bearer'
    if not configuration.api_key[token_name]:
        return False
    return True


def service_logout(service='cloudbreak'):
    """
    Logs out from the service by resetting the token
    Args:
        service (str): 'nifi' or 'registry'; the target service

    Returns:
        (bool): True of access removed, False if still set

    """
    assert service in _valid_services
    set_service_auth_token(token=None, service=service)
    if not get_service_access_status(service, bool_response=True):
        return True
    return False


def get_service_access_status(service='cloudbreak', bool_response=False):
    """
    Gets the access status for the current session

    Args:
        service (str): A String  to indicate which service to target
        bool_response (bool): If True, the function will return False on
            hitting an Error instead of raising it. Useful for connection
            testing.

    Returns:
        (bool) if bool_response, else the Service Access Status of the User
    """
    log.info("Called get_service_access_status with args %s", locals())
    assert service in _valid_services
    assert isinstance(bool_response, bool)
    if bool_response:
        # Assume we are using this as a connection test and therefore disable
        # the Warnings urllib3 will shower us with
        log.debug("- bool_response is True, disabling urllib3 warnings")
        logging.getLogger('urllib3').setLevel(logging.ERROR)
    try:
        out = getattr(whoville, service).AccessApi().get_access_status()
        log.info("Got server response, returning")
        return out
    except urllib3.exceptions.MaxRetryError as e:
        log.debug("- Caught exception %s", type(e))
        if bool_response:
            log.debug("Connection failed with error %s and bool_response is "
                      "True, returning False", e)
            return False
        log.debug("- bool_response is False, raising Exception")
        raise e
