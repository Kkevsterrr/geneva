Defining New Actions
=====================

It is simple to add a new packet-level action to Geneva. 

Let us assume we are adding a new action, called "mytamper", which simply sets the :code:`ipid` field of a packet. 
Our action will take 1 packet and return 1 packet, and we'll start by making it always set the IPID to 1. 

We will subclasss the :code:`Action` class, and specify an :code:`__init__` method and a :code:`run` method. 

In the :code:`__init__` method, we will specify that our action's name is 'mytamper' and can run in :code:`both` inbound and outbound. 
Then, in the :code:`run()` method, we will use Geneva's packet API to set the :code:`ipid` field to 1 and simply return the packet.

.. code-block:: python

    from actions.action import Action

    class MyTamperAction(Action):
        """
        Geneva action to set the IPID to 1.
        """
        # Controls frequency with which this action is chosen by the genetic algorithm
        # during mutation
        frequency = 0

        def __init__(self, environment_id=None):
            Action.__init__(self, "mytamper", "both")

        def run(self, packet, logger):
            """
            The mytamper action returns a modified packet as the left child. 
            """
            logger.debug("  - Changing IPID field to 1")
            packet.set("IP", "ipid", 1)
            return packet, None

And that's it! Now, we can specify this action in our normal strategy DNA: Geneva will discover it dynamically on startup, import it, and we can use it. 

Adding Parameters
^^^^^^^^^^^^^^^^^

Let's now assume we want to make our action take parameters. We will add two new methods: :code:`parse()` and :code:`__str__()`. 
We'll start by adding a new instance variable :code:`self.ipid_value`.

.. code-block:: python

    def __init__(self, environment_id=None, ipid_value=1):
        Action.__init__(self, "mytamper", "both")
        self.ipid_value = ipid_value

Next, we'll add the :code:`__str__` method so when our action is printed in the strategy DNA, its components are too:

.. code-block:: python

    def __str__(self):
        """
        Returns a string representation.
        """
        s = Action.__str__(self)
        s += "{%g}" % self.ipid_value
        return s

Finally, we'll add the :code:`parse()` method so we can parse the value from a string strategy DNA to a live action. 

.. code-block:: python

    def parse(self, string, logger):
        """
        Parses a string representation for this object.
        """
        try:
            if string:
                self.ipid_value = float(string)
        except ValueError:
            logger.exception("Cannot parse ipid_value %s" % string)
            return False

        return True

Putting it all together:

.. code-block:: python

    from actions.action import Action

    class MyTamperAction(Action):
        """
        Geneva action to set the IPID to 1.
        """
        # Controls frequency with which this action is chosen by the genetic algorithm
        # during mutation
        frequency = 0

        def __init__(self, environment_id=None, ipid_value=1):
            Action.__init__(self, "mytamper", "both")
            self.ipid_value = ipid_value

        def run(self, packet, logger):
            """
            The mytamper action returns a modified packet as the left child. 
            """
            logger.debug("  - Changing IPID field to 1")
            packet.set("IP", "ipid", 1)
            return packet, None
    
        def __str__(self):
            """
            Returns a string representation.
            """
            s = Action.__str__(self)
            s += "{%g}" % self.ipid_value
            return s

        def parse(self, string, logger):
            """
            Parses a string representation for this object.
            """
            try:
                if string:
                    self.ipid_value = float(string)
            except ValueError:
                logger.exception("Cannot parse ipid_value %s" % string)
                return False

            return True

And we're done! Now, we can write strategies like: :code:`[TCP:flags:PA]-mytamper{10}-|`, and any TCP packet with the flags field set to :code:`PA` will have its :code:`ipid` field set to 10. 
