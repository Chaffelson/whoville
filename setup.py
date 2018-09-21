#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('docs/history.rst') as history_file:
    history = history_file.read()

proj_version = '0.0.1'

requirements = [
    'urllib3',  # Required for timeouts during security tests
    'six',  # Required for managing Python version compatibility
    'ruamel.yaml<=0.15.42',  # Required for parsing Json/Yaml consistently
    'docker',  # Used to deploy demo assemblies
    'requests[security]',  # Used in utils functions, security extras for Py2
    'pygithub>=1.4',  # For Working with Github support
    'apache-libcloud>=2.3.0'  # Direct Cloud Service interaction
]

setup(
    name='whoville',
    version=proj_version,
    description="Whoville: An opinionated auto-deployer for the Hortonworks Platform",
    long_description=readme + '\n\n' + history,
    author="Daniel Chaffelson",
    author_email='chaffelson@gmail.com',
    url='https://github.com/Chaffelson/whoville',
    download_url='https://github.com/Chaffelson/whoville/archive/' + proj_version + '.tar.gz',
    packages=find_packages(
        include=['whoville']
    ),
    include_package_data=True,
    install_requires=requirements,
    license="Apache Software License 2.0",
    zip_safe=False,
    keywords=['whoville', 'cloudbreak', 'api', 'wrapper'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: User Interfaces'
    ]
)
