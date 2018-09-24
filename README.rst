Whoville
========
An opinionated auto-deployer for the Hortonworks Platform


Quickstart
----------

1. Install / Start a recent version of Docker

https://www.docker.com/get-started

2. Pull the latest whoville Docker image::

    docker pull Chaffelson/whoville

3. Customise a profile.yml::

    curl -sSL https://raw.githubusercontent.com/Chaffelson/whoville/hdp3cbd/profile.RENAME.yml > profile.yml
    vi profile.yml

4. Run the Docker

- Make sure to mount your profile.yml, format is ``'-v /LocalPath/File:/DockerPath/File'``
- Then set PROFILE to the path you have mounted so whoville can find it ``-e PROFILE=/profile.yml``
- Make sure to mount any addition resource volumes specified in your Profile e.g. ``'-v /MyDemos/:/MyDemos/'``
- You can optionally set it to run against your local timezone with ``'-e TZ={timezone}'``

::

    docker run
    -v profile.yml:/profile.yml
    -e PROFILE=/profile.yml
    --name whoville
    whoville:latest

Detailed Guide
--------------

Please see the Github `Wiki <https://github.com/Chaffelson/whoville/wiki>`_

Requirements
------------

Docker
    Everything is included if you use the provided Docker Image for development or deployment

Local
    | Required: Python3.6+
    | Recommended: A Python IDE with inspection and Github support, such as Pycharm

Support
-------
| This software is supplied as-is with no support guarantee under the Apache 2.0 license
| Please raise any Issues on `Github <https://github.com/Chaffelson/whoville/issues/new>`_

History
-------

0.0.1-rc1
    24 Sept 2018

- Initial Release