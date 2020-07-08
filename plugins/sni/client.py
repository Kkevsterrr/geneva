"""
Runs an SNI request, confirms the connection was not torn down
"""

import argparse
import logging
import os
import random
import socket
import subprocess as sp
import sys
import time
import traceback
import urllib.request

import requests

socket.setdefaulttimeout(1)

import external_sites
import actions.utils

from plugins.plugin_client import ClientPlugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))


class SNIClient(ClientPlugin):
    """
    Defines the SNI client.
    """
    name = "sni"

    def __init__(self, args):
        """
        Initializes the sni client.
        """
        ClientPlugin.__init__(self)
        self.args = args

    @staticmethod
    def get_args(command):
        """
        Defines required args for this plugin
        """
        super_args = ClientPlugin.get_args(command)
        parser = argparse.ArgumentParser(description='HTTP Client')

        parser.add_argument('--server', action='store', default="www.wikipedia.org", help='SNI request to make')
        parser.add_argument('--injected-cert-contains', action='store', help='text that injected cert will contain')
        parser.add_argument('--ip', action='store', help='IP address to send the request to')

        args, _ = parser.parse_known_args(command)
        args = vars(args)

        super_args.update(args)
        return super_args

    def run(self, args, logger, engine=None):
        """
        Try to make a forbidden SNI request to the server.
        """
        fitness = 0
        output = ""
        injected_cert_contains = args.get("injected_cert_contains", "")
        try:
            server = args.get("server", "www.wikipedia.org")
            ip = args.get("ip", "")
            cmd = "curl -v --resolve '%s:443:%s' ::%s: https://%s" % (server, ip, server, server)
            logger.debug(cmd)
            output = sp.check_output(cmd, timeout=8, shell=True, stderr=sp.STDOUT)
            logger.debug(output)
        except sp.CalledProcessError as exc:
            logger.debug(exc.output)
            if b"connection reset" in exc.output:
                fitness = -360
            else:
                fitness = -400
        except sp.TimeoutExpired:
            logger.debug("Client timed out")
            fitness = -400
        else:
            logger.debug(output)
            # Check for known signature of the injected certificate
            if injected_cert_contains and injected_cert_contains in output:
                fitness = -360
            else:
                fitness = 400
        return fitness
