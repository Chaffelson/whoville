Whoville
========
An opinionated auto-deployer for the Hortonworks Platform


Quickstart
----------

1. Install / Start a recent version of Docker
    https://www.docker.com/get-started
2. Pull the latest whoville Docker image::

    docker pull Chaffelson/whoville

3. Customise a Profile.yml::

    vi whoville/profile.RENAME.yml

4. Run the Docker
    * Make sure to set PROFILE to the profile.yml you are passing in
    * Make sure to mount any addition resource volumes specified in your Profile

::

    docker run
    -e PROFILE=/profile.yml
    -v profile.yml:/profile.yml
    -v resources/v2:/resources/v2
    --name whoville
    whoville:hdp3cbd 

