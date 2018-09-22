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
    * Make sure to set the profile.yml you are passing in as the first argument of the first -v
    * Make sure to mount any addition resource volumes specified in your Profile as additional -v's

::

    docker run
    -v profile.yml:/whoville/profile.yml
    -v resources/v2:/resources/v2
    -e TZ={timezone}
    --name whoville
    whoville:latest 
