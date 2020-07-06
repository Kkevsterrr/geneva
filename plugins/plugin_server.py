import argparse
import threading
import multiprocessing
import os
import psutil
import socket
import sys
import time

BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASEPATH)
sys.path.append(PROJECT_ROOT)

import actions.sniffer
import engine

from plugins.plugin import Plugin


class ServerPlugin(Plugin):
    """
    Defines superclass for each application plugin.
    """
    def __init__(self):
        self.enabled = True
        self.server_proc = None
        self.sniffer = None
        self.engine = None

    @staticmethod
    def get_args(command):
        """
        Defines required global args for all plugins
        """
        # Do not add a help message; this allows us to collect the arguments from server plugins
        parser = argparse.ArgumentParser(description='Server plugin runner', allow_abbrev=False, add_help=False)
        parser.add_argument('--test-type', action='store', choices=actions.utils.get_plugins(), default="http", help="plugin to launch")
        parser.add_argument('--environment-id', action='store', help="ID of the current environment")
        parser.add_argument('--output-directory', action='store', help="Where to output results")
        parser.add_argument('--no-engine', action="store_true",
                            help="Only run the test without the geneva engine")
        parser.add_argument('--server-side', action="store_true", help="run the Geneva engine on the server side, not the client")
        parser.add_argument('--strategy', action='store', default="", help='strategy to run')
        parser.add_argument('--log', action='store', default="debug",
                        choices=("debug", "info", "warning", "critical", "error"),
                        help="Sets the log level")
        parser.add_argument('--port', action='store', type=int, help='port to run this server on')

        parser.add_argument('--external-server', action='store_true', help="use an external server for testing.")

        parser.add_argument('--sender-ip', action='store', help="IP address of sending machine, used for NAT")
        parser.add_argument('--forward-ip', action='store', help="IP address to forward traffic to")
        parser.add_argument('--routing-ip', action='store', help="routing IP for this computer for server-side evaluation.")
        parser.add_argument('--public-ip', action='store', help="public facing IP for this computer for server-side evaluation.")


        parser.add_argument('--no-wait-for-server', action='store_true', help="disable blocking until the server is bound on a given port")
        parser.add_argument('--wait-for-shutdown', action='store_true', help="monitor for the <eid>.shutdown_server flag to shutdown this server.")

        args, _ = parser.parse_known_args(command)
        return vars(args)

    def start(self, args, logger):
        """
        Runs this plugin.
        """
        logger.debug("Launching %s server" % self.name)

        output_path = os.path.join(PROJECT_ROOT, args["output_directory"])
        eid = args["environment_id"]
        use_engine = not args.get("no_engine", False)
        port = args["port"]
        server_side = args["server_side"]
        log_level = args["log"]
        strategy = args.get("strategy", "")
        assert port, "Need to specify a port in order to launch a sniffer"
        forwarder = {}
        # If NAT options were specified to train as a middle box, set up the engine's
        # NAT configuration
        if args.get("sender_ip"):
            assert args.get("forward_ip")
            assert args.get("sender_ip")
            assert args.get("routing_ip")
            forwarder["forward_ip"] = args["forward_ip"]
            forwarder["sender_ip"] = args["sender_ip"]
            forwarder["routing_ip"] = args["routing_ip"]

        pcap_filename = os.path.join(output_path, "packets", eid + "_server.pcap")

        # We cannot use the context managers as normal here, as this method must return and let the evaluator continue
        # doing its thing. If we used the context managers, they would be cleaned up on method exit.

        # Start a sniffer to capture traffic that the plugin generates
        self.sniffer = actions.sniffer.Sniffer(pcap_filename, int(port), logger).__enter__()

        # Conditionally initialize the engine
        self.engine = engine.Engine(port, strategy, server_side=True, environment_id=eid, output_directory=output_path, log_level=args.get("log", "info"), enabled=use_engine, forwarder=forwarder).__enter__()

        # Run the plugin
        self.server_proc = multiprocessing.Process(target=self.start_thread, args=(args, logger))
        self.server_proc.start()

        # Create a thread to monitor if we need to
        if args.get("wait_for_shutdown"):
            threading.Thread(target=self.wait_for_shutdown, args=(args, logger)).start()

        # Shortcut wait for server if a plugin has disabled it
        if args.get("no_wait_for_server"):
            return

        # Block until the server has started up
        self.wait_for_server(args, logger)

    def start_thread(self, args, logger):
        """
        Calls the given run function, designed to be run in a separate process.
        """
        self.run(args, logger)

    def wait_for_server(self, args, logger):
        """
        Waits for server to startup - returns when the server port is bound to by the server.
        """
        logger.debug("Monitoring for server startup on port %s" % args["port"])
        max_wait = 30
        count = 0
        while count < max_wait:
            if count % 10 == 0:
                logger.debug("Waiting for server port binding")
            # Bind TCP socket
            try:
                with socket.socket() as sock:
                    sock.bind(('', int(args["port"])))
            except OSError:
                break
            time.sleep(0.5)
            count += 1
        else:
            logger.warn("Server never seemed to bind to port")
            return

        self.write_startup_file(args, logger)

    def write_startup_file(self, args, logger):
        """
        Writes a flag file to disk to signal to the evaluator it has started up
        """
        # Touch a file to tell the evaluator we are ready
        flag_file = os.path.join(PROJECT_ROOT, args["output_directory"], "flags", "%s.server_ready" % args["environment_id"])
        open(flag_file, "a").close()
        logger.debug("Server ready.")

    def wait_for_shutdown(self, args, logger):
        """
        Checks for the <eid>.server_shutdown flag to shutdown this server.
        """
        flag_file = os.path.join(PROJECT_ROOT, args["output_directory"], "flags", "%s.server_shutdown" % args["environment_id"])
        while True:
            if os.path.exists(flag_file):
                break
            time.sleep(0.5)
        logger.debug("Server for %s shutting down." % args["environment_id"])
        self.stop()
        logger.debug("Server %s stopped." % args["environment_id"])

    def stop(self):
        """
        Terminates the given process.
        """
        self.engine.__exit__(None, None, None)
        self.sniffer.__exit__(None, None, None)
        # In order to clean up all the child processes a server may have started,
        # iterate over all of the process children and terminate them
        proc = psutil.Process(self.server_proc.pid)
        for child in proc.children(recursive=True):
            child.terminate()
        proc.terminate()

    def punish_fitness(self, fitness, logger):
        """
        Punish fitness.
        """
        return actions.utils.punish_fitness(fitness, logger, self.engine)


def main(command):
    """
    Used to invoke the server plugin from the command line.
    """
    # Must use the superclasses arg parsing first to figure out the plugin to use
    plugin = ServerPlugin.get_args(command)["test_type"]

    # Import that plugin
    mod, cls = actions.utils.import_plugin(plugin, "server")

    # Ask the plugin to parse the args
    plugin_args = cls.get_args(command)

    # Instantiate the plugin
    server_plugin = cls(plugin_args)

    # Define a logger and launch the plugin
    with actions.utils.Logger(plugin_args["output_directory"], __name__, "server", plugin_args["environment_id"], log_level=plugin_args["log"]) as logger:
        server_plugin.start(plugin_args, logger)

if __name__ == "__main__":
    main(sys.argv[1:])
