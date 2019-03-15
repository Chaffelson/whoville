Whoville
========
Cloudy Hortonworks Platforms in under 60 minutes
    A set of demos in a small Docker Image with Orchestration for AWS/GCP/Azure deployment from a simple Profile

Requirements
------------
Hosting Platform
    | You will need an AWS account with rights to deploy machines, assume roles, etc.
    | Please see the Cloudbreak `Requirements <https://docs.hortonworks.com/HDPDocuments/Cloudbreak/Cloudbreak-2.7.1/content/aws-quick/index.html#prerequisites>`_ for creating AWS Roles.

Docker Deployment
    Everything is included if you use the provided Docker Image for development or deployment

Local Deployment
    | Required: Python3.6
    | Recommended: A Python IDE with inspection and Github support, such as Pycharm

Quickstart
----------

1. Customise a profile.yml::

    curl -sSL http://bit.ly/WhovilleProfile > profile.yml && vi profile.yml

2. Install / Start a recent version of `Docker <https://www.docker.com/get-started>`_

3. Export your profile path and run the Docker Image::

    export PROFILE=/path/to/my/profile.yml
    docker run -ti -v ${PROFILE}:/profile.yml:ro chaffelson/whoville:latest

- Make sure to mount any addition resource volumes specified in your Profile e.g. ``'-v /MyDemos/:/MyDemos/'``
- If you want to use interactive Deployment please append '-i' to the 'docker run' command, or see the Detailed Guide below

More Information
----------------

| Suggested setup for `Interactive Development <https://github.com/Chaffelson/whoville/wiki/Development-Setup>`_ in a local Python environment.
| Detailed `Definitions Guide <https://github.com/Chaffelson/whoville/wiki/Usage-Guide>`_ for creating more demos and services.
| `Troubleshooting <https://github.com/Chaffelson/whoville/wiki/Troubleshooting>`_ guide for known issues.

Support
-------
| This software is supplied as-is with no support guarantee under the Apache 2.0 license
| Please raise any Issues on `Github <https://github.com/Chaffelson/whoville/issues/new>`_

You can link to this page from http://bit.ly/HwxQuickstart