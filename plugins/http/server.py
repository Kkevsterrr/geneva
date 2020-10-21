import argparse
import logging
import netifaces
import os
import tempfile
import subprocess

import actions.utils
from plugins.plugin_server import ServerPlugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))


class HTTPServer(ServerPlugin):
    """
    Defines the HTTP client.
    """
    name = "http"
    def __init__(self, args):
        """
        Initializes the HTTP client.
        """
        ServerPlugin.__init__(self)
        self.args = args
        if args:
            self.port = args["port"]
        self.tmp_dir = None

    @staticmethod
    def get_args(command):
        """
        Defines arguments for this plugin
        """
        super_args = ServerPlugin.get_args(command)

        parser = argparse.ArgumentParser(description='HTTP Server')
        parser.add_argument('--port', action='store', default="", help='port to run this server on')

        args, _ = parser.parse_known_args(command)
        args = vars(args)
        super_args.update(args)
        return super_args

    def run(self, args, logger):
        """
        Initializes the HTTP server.
        """
        interface = args.get("interface")
        bind_cmd = []
        if interface:
            bind_addr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            bind_cmd = ["--bind", bind_addr]

        # Create a temporary directory to run out of so we're not hosting files
        self.tmp_dir = tempfile.TemporaryDirectory()

        # Default all output to /dev/null
        stdout, stderr = subprocess.DEVNULL, subprocess.DEVNULL

        # If we're in debug mode, don't send output to /dev/null
        if actions.utils.get_console_log_level() == "debug":
            stdout, stderr = None, None

        # Start the server
        cmd = ["python3", "-m", "http.server", str(args.get('port'))]
        cmd += bind_cmd
        try:
            subprocess.check_call(cmd, stderr=stderr, stdout=stdout, cwd=self.tmp_dir.name)
        except subprocess.CalledProcessError as exc:
            logger.debug("Server exited: %s", str(exc))

    def stop(self):
        """
        Stops this server.
        """
        if self.tmp_dir:
            self.tmp_dir.cleanup()
        ServerPlugin.stop(self)
