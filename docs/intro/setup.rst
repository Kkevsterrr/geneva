Setup
=====

Geneva has been developed and tested for Centos or Debian-based systems. Due to
limitations of netfilter and raw sockets, Geneva does not work on OS X or
Windows at this time and requires *python3.6*.

Install netfilterqueue dependencies:

.. code-block:: bash

    # sudo apt-get install build-essential python-dev libnetfilter-queue-dev libffi-dev libssl-dev iptables python3-pip


Install Python dependencies:

.. code-block:: bash

    # python3 -m pip install -r requirements.txt

Docker (Optional)
^^^^^^^^^^^^^^^^^

Geneva has an internal system that can be used to test strategies using Docker.
This is largely used for testing fitness functions with the mock censors
provided - it is **not used for training against real censors**. Due to
limitations of raw sockets inside docker containers in many builds of Docker,
Geneva cannot be used inside a docker container to communicate with hosts
outside of Docker's internal network.  

When used with Docker, Geneva will spin up three docker containers: a client, a
censor, and a server, and configure the networking routes such that the client
and server communicate through the censor. To evaluate strategies (see much more detail in the evaluation section),
Geneva will run the plugin client inside the client and
attempt to communicate with the server through the censor. 

Each docker container used by the evaluator runs out of the same base container.

Build the base container with:

.. code-block:: bash

    docker build -t base:latest -f docker/Dockerfile .

Optionally, to manually run/inspect the docker image to explore the image, run:

.. code-block:: bash

    docker run -it base
