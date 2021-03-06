# coding: utf-8

"""
    Cloudbreak API

    Cloudbreak is a powerful left surf that breaks over a coral reef, a mile off southwest the island of Tavarua, Fiji. Cloudbreak is a cloud agnostic Hadoop as a Service API. Abstracts the provisioning and ease management and monitoring of on-demand clusters. SequenceIQ's Cloudbreak is a RESTful application development platform with the goal of helping developers to build solutions for deploying Hadoop YARN clusters in different environments. Once it is deployed in your favourite servlet container it exposes a REST API allowing to span up Hadoop clusters of arbitary sizes and cloud providers. Provisioning Hadoop has never been easier. Cloudbreak is built on the foundation of cloud providers API (Amazon AWS, Microsoft Azure, Google Cloud Platform, Openstack), Apache Ambari, Docker lightweight containers, Swarm and Consul. For further product documentation follow the link: <a href=\"http://hortonworks.com/apache/cloudbreak/\">http://hortonworks.com/apache/cloudbreak/</a>

    OpenAPI spec version: 2.9.0
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from pprint import pformat
from six import iteritems
import re


class AccountPreferencesRequest(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """


    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'platforms': 'str',
        'smartsense_enabled': 'bool',
        'default_tags': 'dict(str, str)'
    }

    attribute_map = {
        'platforms': 'platforms',
        'smartsense_enabled': 'smartsenseEnabled',
        'default_tags': 'defaultTags'
    }

    def __init__(self, platforms=None, smartsense_enabled=False, default_tags=None):
        """
        AccountPreferencesRequest - a model defined in Swagger
        """

        self._platforms = None
        self._smartsense_enabled = None
        self._default_tags = None

        if platforms is not None:
          self.platforms = platforms
        if smartsense_enabled is not None:
          self.smartsense_enabled = smartsense_enabled
        if default_tags is not None:
          self.default_tags = default_tags

    @property
    def platforms(self):
        """
        Gets the platforms of this AccountPreferencesRequest.
        list of the cloudplatforms visible on the UI

        :return: The platforms of this AccountPreferencesRequest.
        :rtype: str
        """
        return self._platforms

    @platforms.setter
    def platforms(self, platforms):
        """
        Sets the platforms of this AccountPreferencesRequest.
        list of the cloudplatforms visible on the UI

        :param platforms: The platforms of this AccountPreferencesRequest.
        :type: str
        """

        self._platforms = platforms

    @property
    def smartsense_enabled(self):
        """
        Gets the smartsense_enabled of this AccountPreferencesRequest.
        smartsense enabled on the UI

        :return: The smartsense_enabled of this AccountPreferencesRequest.
        :rtype: bool
        """
        return self._smartsense_enabled

    @smartsense_enabled.setter
    def smartsense_enabled(self, smartsense_enabled):
        """
        Sets the smartsense_enabled of this AccountPreferencesRequest.
        smartsense enabled on the UI

        :param smartsense_enabled: The smartsense_enabled of this AccountPreferencesRequest.
        :type: bool
        """

        self._smartsense_enabled = smartsense_enabled

    @property
    def default_tags(self):
        """
        Gets the default_tags of this AccountPreferencesRequest.
        default tags for the resources created

        :return: The default_tags of this AccountPreferencesRequest.
        :rtype: dict(str, str)
        """
        return self._default_tags

    @default_tags.setter
    def default_tags(self, default_tags):
        """
        Sets the default_tags of this AccountPreferencesRequest.
        default tags for the resources created

        :param default_tags: The default_tags of this AccountPreferencesRequest.
        :type: dict(str, str)
        """

        self._default_tags = default_tags

    def to_dict(self):
        """
        Returns the model properties as a dict
        """
        result = {}

        for attr, _ in iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """
        Returns the string representation of the model
        """
        return pformat(self.to_dict())

    def __repr__(self):
        """
        For `print` and `pprint`
        """
        return self.to_str()

    def __eq__(self, other):
        """
        Returns true if both objects are equal
        """
        if not isinstance(other, AccountPreferencesRequest):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        Returns true if both objects are not equal
        """
        return not self == other
