Whoville
========
An opinionated auto-deployer for the Hortonworks Platform


Requirements
------------
Hosting Platform
    | You will need an AWS account with rights to deploy machines, assume roles, etc.
    | Please see the Cloudbreak `Requirements <https://docs.hortonworks.com/HDPDocuments/Cloudbreak/Cloudbreak-2.7.1/content/aws-quick/index.html#prerequisites>`_

Docker Deployment
    Everything is included if you use the provided Docker Image for development or deployment

Local Deployment
    | Required: Python3.6+
    | Recommended: A Python IDE with inspection and Github support, such as Pycharm

Quickstart
----------

1. Customise a profile.yml::

    curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/master/profile.RENAME.yml > profile.yml
    vi profile.yml

2. Install / Start a recent version of `Docker <https://www.docker.com/get-started>`_

3. Run the Automated Tooling

::

    docker run
    -v $(pwd)/profile.yml:/profile.yml:ro
    -e PROFILE=/profile.yml
    --name whoville
    chaffelson/whoville:latest

- Set your Profile so whoville can find it per the above parameters
- Make sure to mount any addition resource volumes specified in your Profile e.g. ``'-v /MyDemos/:/MyDemos/'``
- You can optionally set it to run against your local timezone with ``'-e TZ={timezone}'``

4. If you want to use interactive Deployment please see the Detailed Guide below.

More Information
----------------

| Suggested setup for `Interactive Development <https://github.com/Chaffelson/whoville/wiki/Development-Setup>`_ in a local Python environment.
| Detailed `Definitions Guide <https://github.com/Chaffelson/whoville/wiki/Usage-Guide>`_ for creating more demos and services.
| `Troubleshooting <https://github.com/Chaffelson/whoville/wiki/Troubleshooting>`_ guide for known issues.

Support
-------
| This software is supplied as-is with no support guarantee under the Apache 2.0 license
| Please raise any Issues on `Github <https://github.com/Chaffelson/whoville/issues/new>`_
