import argparse
import os
from plugins.plugin_client import ClientPlugin
from subprocess import Popen, PIPE, TimeoutExpired


class SNIIndiaClient(ClientPlugin):
    """
    Defines the SNI client.
    """
    name = "airtel_sni"

    def __init__(self, args):
        """
        Initializes the SNI client.
        """
        ClientPlugin.__init__(self)
        self.args = args

    @staticmethod
    def get_args(command):
        """
        Defines args for this plugin
        """
        super_args = ClientPlugin.get_args(command)

        parser = argparse.ArgumentParser(description="India SNI client")

        parser.add_argument("--server", action='store', help='server to connect to')
        parser.add_argument("--sni", action="store", help="sni to include in tls client hello")
        parser.add_argument("--timeout", action="store", help="timeout for requests", type=int)

        args, _ = parser.parse_known_args(command)
        args = vars(args)
        super_args.update(args)

        return super_args

    def run(self, args, logger, engine=None):
        """
        Try to start a TLS handshake with the SNI set to a censored website and see if we receive a RST
        """

        fitness = 0
        port = int(args["port"])
        server = args["server"]
        sni = args["sni"]
        timeout = args["timeout"]

        proc = Popen(["openssl", "s_client", "-connect" ,"%s:%d" % (server, port), "-servername", sni], stdin=PIPE, stdout=PIPE, stderr=PIPE)

        try:
            outs, errs = proc.communicate(input=b"Q", timeout=timeout)

            if b"read 0 bytes" in outs:
                fitness -= 90
                logger.debug("TLS handshake blocked")
            elif proc.returncode == 0:
                fitness += 100
                logger.debug("TLS handshake successful")
            else:
                fitness -= 100
                logger.debug("Unknown error")
        except TimeoutExpired:
            proc.kill()
            fitness -= 100
            logger.debug("Timeout")

        return fitness * 4
