Whoville
========
An opinionated auto-deployer for the Hortonworks Platform


Quickstart
----------

1. Install / Start a recent version of Docker
    https://www.docker.com/get-started
2. Pull the latest whoville Docker image::

    docker pull Chaffelson/whoville

3. Customise and rename profile.yml::

    mv profile.RENAME.yml profile.yml && vi profile.yml

4. Run the Docker
    * Make sure to mount your profile.yml, format is '-v /LocalPath:/DockerPath'
    * Then set PROFILE to the path you have mounted so whoville can find it
    * Make sure to mount any addition resource volumes specified in your Profile e.g. '-v /MyDemos/:/MyDemos/'
    * You can optionally set it to run against your local timezone with '-e TZ={timezone}'

::

    docker run
    -v profile.yml:/profile.yml
    -e PROFILE=/profile.yml
    --name whoville
    whoville:latest