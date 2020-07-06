Engine
======

The strategy engine (:code:`engine.py`) applies a strategy to a network connection. The engine works by capturing all traffic to/from a specified port. Packets that match an active trigger are run through the associated action-tree, and packets that emerge from the tree are sent on the wire. 

.. code-block:: bash

    # python3 engine.py --server-port 80 --strategy "\/" --log debug
    2019-10-14 16:34:45 DEBUG:[ENGINE] Engine created with strategy \/ (ID bm3kdw3r) to port 80
    2019-10-14 16:34:45 DEBUG:[ENGINE] Configuring iptables rules
    2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 1
    2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 2
    2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A OUTPUT -p udp --sport 80 -j NFQUEUE --queue-num 1
    2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A INPUT -p udp --dport 80 -j NFQUEUE --queue-num 2


The engine also has a Python API for using it in your application. It can be used as a context manager or invoked in the background as a thread. 
For example, consider the following simple application. 

.. code-block:: python

    import os
    import engine

    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as eng:
        os.system("curl http://example.com?q=ultrasurf")

This script creates an instance of the engine with a specified strategy, and that strategy will be running for everything within the context manager. When the context manager exits, the engine will clean itself up. See the :code:`examples/` folder for more use cases of the engine. 

.. note:: Due to limitations of scapy and NFQueue, the engine cannot be used to communicate with localhost.

