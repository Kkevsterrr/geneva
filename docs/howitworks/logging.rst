Logging
=======

Geneva uses multiple loggers during execution. :code:`evolve.py` creates the parent logger, and creates a subfolder of the current time under the :code:`trials/` directory. 

Within this directory, it creates 5 subfolders: 
 - :code:`data`: used for misc. data related to strategy evaluation
 - :code:`flags`: used to write status files to set events
 - :code:`generations`: used to store the full generations and hall of fame after each generation
 - :code:`logs`: stores logs for evaluation
 - :code:`packets`: stores packet captures during strategy evolution

The two main log files used by :code:`evolve.py` are :code:`ga.log` and :code:`ga_debug.log` (everything in debug mode). As each strategy is evaluated, a :code:`<id>_engine.log`, :code:`<id>_server.log`, and :code:`<id>_client.log` files are generated.

For example, one run's output could be: 

.. code-block:: none
    
    # ls trials
    2020-03-23_20:03:08

    # ls trials/2020-03-23_20:03:08
    data        flags       generations logs        packets

    # ls trials/2020-03-23_20:03:08/logs
    ga.log      ga_debug.log    zhak1n81_client.log  zhak1n81_engine.log  zhak1n81_server.log


