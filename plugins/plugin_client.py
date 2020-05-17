import argparse
import os
import sys
import time

from scapy.all import send, IP, TCP, Raw

BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASEPATH)
sys.path.append(PROJECT_ROOT)

import actions.sniffer
import engine

from plugins.plugin import Plugin


class ClientPlugin(Plugin):
    """
    Defines superclass for each application plugin.
    """
    def __init__(self):
        self.enabled = True

    @staticmethod
    def get_args(command):
        """
        Defines required global args for all plugins
        """
        # Do not add a help message; this allows us to collect the arguments from server plugins
        parser = argparse.ArgumentParser(description='Client plugin runner', allow_abbrev=False, add_help=False)
        parser.add_argument('--test-type', action='store', choices=actions.utils.get_plugins(), default="http", help="plugin to launch")
        parser.add_argument('--environment-id', action='store', help="ID of the current environment")
        parser.add_argument('--output-directory', action='store', help="Where to output results")
        parser.add_argument('--no-engine', action="store_true",
                            help="Only run the test without the geneva engine")
        parser.add_argument('--server-side', action="store_true", help="run the Geneva engine on the server side, not the client")
        parser.add_argument('--strategy', action='store', default="", help='strategy to run')
        parser.add_argument('--server', action='store', help="server to connect to")
        parser.add_argument('--log', action='store', default="debug",
                        choices=("debug", "info", "warning", "critical", "error"),
                        help="Sets the log level")
        parser.add_argument('--port', action='store', type=int, help='port to run this server on')

        parser.add_argument('--wait-for-censor', action='store_true', help='send control packets to the censor to get startup confirmation')

        parser.add_argument('--bad-word', action='store', help="forbidden word to test with", default="ultrasurf")

        args, _ = parser.parse_known_args(command)
        return vars(args)

    def start(self, args, logger):
        """
        Runs this plugin.
        """
        logger.debug("Launching %s" % self.name)
        fitness = -1000

        output_path = os.path.join(PROJECT_ROOT, args.get("output_directory"))
        eid = args.get("environment_id")
        use_engine = not args.get("no_engine")
        port = args.get("port")
        server_side = args.get("server_side")
        assert port, "Need to specify a port in order to launch a sniffer"

        pcap_filename = os.path.join(output_path, "packets", eid + "_client.pcap")

        # Start a sniffer to capture traffic that the plugin generates
        with actions.sniffer.Sniffer(pcap_filename, port, logger) as sniff:

            # Conditionally initialize the engine
            with engine.Engine(port, args.get("strategy"), server_side=False, environment_id=eid, output_directory=output_path, log_level=args.get("log", "info"), enabled=use_engine) as eng:
                # Wait for the censor to start up, if one is running
                if args.get("wait_for_censor"):
                    self.wait_for_censor(args.get("server"), port, eid, output_path)

                # Run the plugin
                fitness = self.run(args, logger, engine=eng)
                logger.debug("Plugin client has finished.")
                if use_engine:
                    fitness = actions.utils.punish_fitness(fitness, logger, eng)

        # If fitness files are disabled, just return
        if args.get("no_fitness_file"):
            return fitness

        logger.debug("Fitness: %d", fitness)

        actions.utils.write_fitness(fitness, output_path, eid)
        return fitness

    def wait_for_censor(self, serverip, port, environment_id, log_dir):
        """
        Sends control packets to the censor for up to 20 seconds until it's ready.
        """
        for _ in range(0, 200):
            check = IP(dst=serverip)/TCP(dport=int(port), sport=2222, seq=13337)/Raw(load="checking")
            send(check, verbose=False)
            ready_path = os.path.join(BASEPATH, log_dir, actions.utils.FLAGFOLDER, "%s.censor_ready" % environment_id)
            if os.path.exists(ready_path):
                os.system("rm %s" % ready_path)
                break
            time.sleep(0.1)
        else:
            return False
        return True


def main(command):
    """
    Used to invoke the plugin client from the command line.
    """
    # Must use the superclasses arg parsing first to figure out the plugin to use
    plugin = ClientPlugin.get_args(command)["test_type"]

    # Import that plugin
    _, cls = actions.utils.import_plugin(plugin, "client")

    # Ask the plugin to parse the args
    plugin_args = cls.get_args(command)

    # Instantiate the plugin
    client_plugin = cls(plugin_args)

    # Define a logger and launch the plugin
    with actions.utils.Logger(plugin_args["output_directory"], __name__, "client", plugin_args["environment_id"], log_level=plugin_args.get("log")) as logger:
        client_plugin.start(plugin_args, logger)

if __name__ == "__main__":
    main(sys.argv[1:])
