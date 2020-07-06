Adding New Plugins
==================

This section will describe the process to add a new application plugin to Geneva.
Application plugins serve as the fitness function for Geneva during evolution,
and allow it to evolve strategies to defeat certain types of censorship. 

Plugins are run by the Evaluator; if you have not yet read how the Evaluator
works, see the :ref:`Strategy Evaluation` section.

There are three types of plugins: clients, servers, and overriding plugins. 
A developer can choose to implement any one of, or all three of these plugins.

For this section, we will build an example plugin and walk through the existing
plugins to tour through the plugin API. 

Plugins are expected to be in the :code:`plugins/` folder in geneva's repo. The
folder name is the plugin name, and Geneva will discover these automatically.
Plugins are specified to the evaluator or evolve with the :code:`--test-type`
flag. Within the plugin folder, plugins must adhere to the following naming
scheme:

- :code:`client.py` - for plugin clients
- :code:`server.py` - for plugin servers [optional]
- :code:`plugin.py` - for an overriding plugin to customize logic [optional]

:code:`server.py` and :code:`plugin.py` are optional. The server plugin is
required to do server-side evaluation, but the overriding plugin definition is
only required to if a developer wishes to override the evaluator's default
behavior. 

If an overriding plugin is provided, the evaluator will simply invoke it at the
start of strategy evaluation and the overriding plugin will be responsible for
calling the client and server. This section will assume that no overriding
plugin is specified to describe the evaluator's default behavior with plugins,
and cover use cases for overriding plugins at the end.

Depending on the evaluation setup, some (or all) of these plugins will be used
during evaluation. For example, during an exclusively client-side evaluation,
only the client plugin is needed.

Client Plugins
^^^^^^^^^^^^^^

During exclusively client-side evolution, the evaluator will start the engine
with the strategy under evaluation, and then run the client plugin. During
server-side evolution, the evaluator will run the engine on the server-side,
start the server plugin, and then start the client plugin via an SSH session to
the remote client worker. (See :ref:`Adding a Worker` on how external workers
can be used).

The client plugin subclasses from the PluginClient object. To tour through the
API, we will walk through the development of a custom client plugin. 

Writing Our Own
~~~~~~~~~~~~~~~

Let us write a fitness function to test Iran's whitelisting system. 

Iran's protocol whitelister was a recently deployed new censorship mechanism to
censor non-whitelisted protocols on certain ports (53, 80, 443). We deployed
Geneva against the whitelister, and discovered multiple ways to evade it in just
one evolution of the genetic algorithm. (The results of that investigation is
located `here <https://geneva.cs.umd.edu/posts/iran-whitelister>`_). 

The whitelister worked by checking the first 2 packets of a flow, and if they
did not match a fingerprint, it would destroy the flow. 

In order to run Geneva against whitelister, we will define a client plugin that
will try to trigger the whitelister and record whether the whitelister
successfully censored its connection or not. 

First, let's make a new folder in the :code:`plugins/` directory called
"whitelister". We'll create a "client.py" and create the plugin object as 
a subclass of ClientPlugin. 

.. code-block:: python

    class WhitelisterClient(ClientPlugin):
        """
        Defines the whitelister client.
        """
        name = "whitelister"

        def __init__(self, args):
            """
            Initializes the whitelister client.
            """
            ClientPlugin.__init__(self)
            self.args = args


Done! Next, let's define argument parsing for this plugin. Geneva uses a
pass-through system of argument parsing: when command-line arguments are
specified, evolve.py parses the options it knows and passes the rest to the
evaluator. The evaluator prases the options it knows, and passes the list to the
plugins. This allows developers to easily add their own arguments just to their
plugin and use them from the command-line without changing any of the
intermediate code. 

In this case, we need our client to make a TCP connection to a server located
outside of Iran to send our whitelister triggering messages to. Let's add an
argument so the user can specify which server to connect to. 

We can do this by adding a :code:`get_args` static method. The evaluator will
call this method when the plugin is created and give it the full command line
list, so the plugin is free to parse it how it chooses. For this example, we
will use the standard :code:`argparse` library.

Since the superclass also defines args, we'll pass the command line list up to
the super class as well to collect those arguments. 

.. code-block:: python

        @staticmethod
        def get_args(command):
            """
            Defines args for this plugin
            """
            super_args = ClientPlugin.get_args(command)
            parser = argparse.ArgumentParser(description='Whitelister Client')

            parser.add_argument('--server', action='store', help="server to connect to")

            args, _ = parser.parse_known_args(command)
            args = vars(args)

            super_args.update(args)
            return super_args

Now, we just need to define a :code:`run()` method. The :code:`run()` method is
called by the evaluator to run the plugin. It provides the parsed arguments, a
logger to log with, and a reference to an instance of the strategy engine that
is running the strategy (see :ref:`Engine` for more information on how the
engine works.)

Let's start by defining the run method. We'll pull out the argument for the
server we defined earlier, connect to it with a python socket, and then just
send "G", "E", and "T" in separate messages to trigger the whitelister. Since
the whitelister censors connections by blackholing them, if the strategy failed
to defeat the whitelister, we would expect our network connection to timeout;
if we can send our messages and get a response from the server, the strategy
under evaluation may have defeated the whitelister. 

.. code-block:: python

       def run(self, args, logger, engine=None):
            """
            Try to open a socket, send two messages, and see if the messages
            time out.
            """
            fitness = 0
            port = int(args["port"])
            server = args["server"]
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(3)
                client.connect((server, port))
                client.sendall(b"G")
                time.sleep(0.25)
                client.sendall(b"E")
                time.sleep(0.25)
                client.sendall(b"T\r\n\r\n")
                server_data = client.recv(1024)
                logger.debug("Data recieved: %s", server_data.decode('utf-8', 'ignore'))
                if server_data:
                    fitness += 100
                else:
                    fitness -= 90
                client.close()
                # ...

Now we just need to define the error handling for this code. This is critical to
the fitness function: we want to kill off strategies that damage the underlying
TCP connection, so Geneva does not waste time searching this space of
strategies.

Our goal is to set the fitness metric such that a *censorship event has a higher
fitness than the strategy damaging the connection*. Since we can distinguish
these cases based on the socket error, we will set a lower fitness if any other
exception is raised besides the timeout. 

Lastly, we'll inflate the numerical fitness metric to make it a larger number.
The evaluator does additional punishments to the fitness score based on the
strategy (see :ref:`Strategy Evaluation`), so we want the number to be
sufficiently large to not push succeeding strategies to negative numbers.

.. code-block:: python

            except socket.timeout:
                logger.debug("Client: Timeout")
                fitness -= 90
            except socket.error as exc:
                fitness -= 100
                logger.exception("Socket error caught in client echo test.")
            finally:
                logger.debug("Client finished whitelister test.")
        return fitness * 4 


Putting it all together: 

.. code-block:: python

    class WhitelisterClient(ClientPlugin):
        """
        Defines the whitelister client.
        """
        name = "whitelister"

        def __init__(self, args):
            """
            Initializes the whitelister client.
            """
            ClientPlugin.__init__(self)
            self.args = args

        @staticmethod
        def get_args(command):
            """
            Defines args for this plugin
            """
            super_args = ClientPlugin.get_args(command)
            parser = argparse.ArgumentParser(description='Whitelister Client')

            parser.add_argument('--server', action='store', help="server to connect to")

            args, _ = parser.parse_known_args(command)
            args = vars(args)

            super_args.update(args)
            return super_args

        def run(self, args, logger, engine=None):
            """
            Try to open a socket, send two messages, and see if the messages
            time out.
            """
            fitness = 0
            port = int(args["port"])
            server = args["server"]
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(3)
                client.connect((server, port))
                client.sendall(b"G")
                time.sleep(0.25)
                client.sendall(b"E")
                time.sleep(0.25)
                client.sendall(b"T\r\n\r\n")
                server_data = client.recv(1024)
                logger.debug("Data recieved: %s", server_data.decode('utf-8', 'ignore'))
                if server_data:
                    fitness += 100
                else:
                    fitness -= 90
                client.close()
            except socket.timeout:
                logger.debug("Client: Timeout")
                fitness -= 90
            except socket.error as exc:
                fitness -= 100
                logger.exception("Socket error caught in client echo test.")
            finally:
                logger.debug("Client finished whitelister test.")
        return fitness * 4 

Server Plugins
^^^^^^^^^^^^^^

Coming soon! 

Override Plugins
^^^^^^^^^^^^^^^^

Coming soon!
