Adding a Worker
===============

Below is how to add a new external client worker to Geneva. An external client worker is an external, SSH-accessible machine under the control of the user running Geneva for the purpose of performing strategy evaluation from outside the censored regime. 

Geneva expects each of its worker to be defined in the :code:`workers` folder. 

For this section, let us assume we are trying to allow Geneva to use a new external worker located in China.

First, make a new subfolder for that worker under the :code:`workers/` directory.

.. code-block:: none

    # mkdir workers/test
    # ls workers/
    example test

Each worker is defined by a :code:`worker.json` file located inside its subfolder. 

The structure of the worker looks like this:

.. code-block:: json

    {
        "name": "test",
        "ip": "<ip_here>",
        "hostname": "<hostname>",
        "username": "user",
        "password": null,
        "port": 22,
        "python": "python3",
        "city": "Bejing",
        "keyfile": "example.pem",
        "country": "China",
        "geneva_path": "~/geneva"
    }

If passwordless SSH is used, you can optionally specify a keyfile for it to SSH with. 

Once this is defined, we can specify :code:`--external-client test` during strategy evaluation, and the evaluator will SSH to this worker for training!

.. note:: Remember, external client workers must have Geneva cloned to the directory specified in :code:`geneva_path` and depencies set up before use. 
