"""
DNS Plugin driver

Overrides the default evaluator plugin handling so we can check for legit IPs for UDP tests.
"""

import argparse
import calendar
import copy
import logging
import os
import random
import socket
import sys
import tempfile
import time
import traceback
import urllib.request

import requests

socket.setdefaulttimeout(1)

import actions.utils

from plugins.plugin import Plugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASEPATH))


class DNSPluginRunner(Plugin):
    """
    Defines the DNS plugin runner.
    """
    name = "dns"

    def __init__(self, args):
        """
        Marks this plugin as enabled
        """
        self.enabled = True

    def check_legit_ip(self, ip, logger, domain="facebook"):
        """
        Helper method to check if the given IP address is serving web content.
        """
        url = "http://%s" % ip
        logger.debug("Checking %s if returned legitimate %s" % (url, domain))
        try:
            res = requests.get(url, allow_redirects=False, timeout=3)
            if res.status_code == 400:
                res.raise_for_status()
            # If we got a 301 redirect, the res.text will be empty, but facebook will show up in
            # the headers
            for header in res.headers:
                if domain in res.headers[header]:
                    return True
            # Otherwise, check the res.text
            return domain in res.text
        except Exception as exc:
            logger.debug("Exception caught in checking DNS result %s: %s", url, exc)
            return False

    def start(self, args, evaluator, environment, ind, logger):
        """
        Runs the plugins
        """
        # Start the server
        port = args.get("port", 53)
        use_tcp = evaluator.client_args.get("use_tcp", False)

        if port != 53:
            logger.warning("Warning: Given port %s, but GFW only censors on port 53.", str(port))

        # Disable wait for server - it checks based on binding to a TCP port
        evaluator.server_args.update({"no_wait_for_server" : True})

        # If we're given a server to start, start it now
        if evaluator.server_cls and not args.get("external_server"):
            # If a test using TCP has been requested, switch the server to that mode
            if use_tcp:
                evaluator.server_args.update({"listener": "socket_TCP"})
            server = evaluator.start_server(evaluator.server_args, environment, logger)
            evaluator.client_args.update({"dns_server": evaluator.args["server"]})

        fitness = evaluator.run_client(evaluator.client_args, environment, logger)

        if evaluator.server_cls and not evaluator.args["external_server"]:
            evaluator.stop_server(environment, server)

        evaluator.read_fitness(ind)

        # If the engine ran on the server side, ask that it punish fitness
        if evaluator.args["server_side"]:
            ind.fitness = server.punish_fitness(ind.fitness, logger)
            # When performing a DNS test, a timeout is indistinguishable from
            # a reset, which means we can't tell if the strategy broke the packet
            # stream, or if the censor caught us. Strategies that break the stream
            # should be punished more harshly, so raise the fitness slightly
            # if the engine detected censorship for failed DNS tests.
            if use_tcp and server.engine and server.engine.censorship_detected and ind.fitness < 0:
                logger.debug("Censorship detected - adjusting positively for not killing stream")
                ind.fitness += 40

            output_path = os.path.join(PROJECT_ROOT, evaluator.client_args.get("output_directory"))
            fitpath = os.path.join(PROJECT_ROOT, output_path, actions.utils.FLAGFOLDER, environment["id"]) + ".fitness"
            with open(fitpath, "w") as fitfile:
                fitfile.write(str(ind.fitness))

        if evaluator.args["external_client"]:
            command = 'cat %s/%s/%s/%s.dnsresult' % (environment["worker"]["geneva_path"], evaluator.args["output_directory"], actions.utils.FLAGFOLDER, environment["id"])
            dns_result, error_lines = evaluator.remote_exec_cmd(environment["remote"], command, logger)
            if not dns_result:
                logger.debug("Failed to get DNS result.")
            else:
                result = dns_result[0]
                logger.debug("Got result: %s" % result)
                # If the IP we got back was bad, we must fail the strategy
                if not self.check_legit_ip(result, logger, domain="facebook"):
                    ind.fitness = -360
                    output_path = os.path.join(PROJECT_ROOT, evaluator.client_args.get("output_directory"))
                    fitpath = os.path.join(PROJECT_ROOT, output_path, actions.utils.FLAGFOLDER, environment["id"]) + ".fitness"
                    with open(fitpath, "w") as fitfile:
                        fitfile.write(str(ind.fitness))

        # Log the fitness
        #logger.info("[%s] Fitness %s: %s" % (ind.environment_id, str(ind.fitness), str(ind)))

        return ind.environment_id, ind.fitness

    @staticmethod
    def get_args(command):
        """
        Defines required global args for this plugin
        """
        parser = argparse.ArgumentParser(description='DNS plugin runner', allow_abbrev=False)
        parser.add_argument('--use-tcp', action='store_true', help='leverage TCP for this plugin')
        parser.add_argument('--environment-id', action='store', help="ID of the current environment")
        parser.add_argument('--output-directory', action='store', help="Where to output results")
        parser.add_argument('--port', action='store', type=int, default=53, help='port to use')
        args, _ = parser.parse_known_args(command)
        return vars(args)
