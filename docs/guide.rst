Guidebook
=========

Local Development
^^^^^^^^^^^^^^^^^

Github Checkout
---------------

You may find it convenient to do a thin checkout the current working branch::

    git clone --depth 1 -b hdp3cbd https://github.com/Chaffelson/whoville.git

Set your PYTHONPATH
-------------------
When working in a Python commandline, it is strongly recommended to add the root directory of the project to your Python Path::

    export PYTHONPATH="${PYTHONPATH}:/path/to/whoville"

Note that if you are working in an IDE like PyCharm or Eclipse, it will probably do this for you.

Create your Profile
-------------------
| Whoville relies on a short Profile file defined in YAML to bootstrap itself.
| An example is provided in the project root (profile.RENAME.yml), you should rename this to 'profile.yml' and edit it with your information. 
| Details on each parameter are commented in-line in the example file.


Interactive Development
-----------------------
If you wish to interactively use the deployment manager (Whoville's Mayor) then you will likely find it easiest to import the Mayor's namespace::

    python3
    from whoville.mayor import *

The current state of Whoville is kept in an object called 'horton', which is updated by each step of the process laid out in mayor.py. All information about Whoville should be found either in Horton's memory or your Profile

Local Docker
------------
| There is a convenient Dockerfile for local development in docker/v2/localdev/Dockerfile
| It is suggested that you run the docker build command from the root of the project using the -f flag to reduce complexity when passing in the code base and other definitions

::

    docker build -f="./docker/v2/localdev/Dockerfile" -t whoville:hdp3cbd . 
    && docker run
    -v /whoville:/whoville
    --env PROFILE=/whoville/profile.yml
    --name whoville whoville:hdp3cbd

Troubleshooting
^^^^^^^^^^^^^^^

RequestExpired: Request has expired
-----------------------------------

This is caused by the time in the Docker image being too far out of sync. Common with Docker on Mac due to timesync issues after sleep. Can be fixed with the following to resyny the Docker VM clock with the OS::

    docker run --rm --privileged alpine hwclock -s

Cloudbreak unavailable, Deployment Timeout, etc.
------------------------------------------------

Cloudbreak may not be available for various reasons, here are some useful steps

Cmdline Login::

    ssh -i <ssh key in your profile> centos@<Cloudbreak IP or FQDN>
    sudo su -
    ls /root  # Cloudbreak control directory, if install succeeded
    cat /var/log/cloud-init.log  # Server bootstrap, can indicate initialization errors
    cat /var/log/cbd_bootstrap_centos7.log  # Cloudbreak installer log, can indicate install failure
    curl http://169.254.169.254/latest/user-data  # Check the passed-in build script
    cd /root && cbd restart  # Restarting Cloudbreak, may provide a view of error basis
