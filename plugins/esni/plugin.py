"""
ESNI Plugin driver

Overrides the default evaluator plugin handling so we can check if the server timed out on recv.
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


class ESNIPluginRunner(Plugin):
    """
    Defines the ESNI plugin runner.
    """
    name = "esni"

    def __init__(self, args):
        """
        Marks this plugin as enabled
        """
        self.enabled = True

    def start(self, args, evaluator, environment, ind, logger):
        """
        Runs the plugins
        """
        # Start the server
        port = random.randint(10000, 65000)
        evaluator.client_args.update({"port": port})
        evaluator.server_args.update({"port": port})

        # If we're given a server to start, start it now
        if evaluator.server_cls and not args.get("external_server"):
            # If a test using TCP has been requested, switch the server to that mode
            server = evaluator.start_server(evaluator.server_args, environment, logger)
            evaluator.client_args.update({"server": evaluator.args["server"]})

        fitness = evaluator.run_client(evaluator.client_args, environment, logger)

        if evaluator.server_cls and not evaluator.args["external_server"]:
            evaluator.stop_server(environment, server)

        evaluator.read_fitness(ind)

        # If the engine ran on the server side, ask that it punish fitness
        if evaluator.args["server_side"]:
            ind.fitness = server.punish_fitness(ind.fitness, logger)
            output_path = os.path.join(PROJECT_ROOT, evaluator.client_args.get("output_directory"))
            fitpath = os.path.join(PROJECT_ROOT, output_path, actions.utils.FLAGFOLDER, environment["id"]) + ".fitness"
            with open(fitpath, "w") as fitfile:
                fitfile.write(str(ind.fitness))

        if evaluator.server_cls and not evaluator.args["external_server"]:
            logger.debug("CHECKING FOR SERVER TIMEOUT")
            output_path = os.path.join(PROJECT_ROOT, evaluator.client_args.get("output_directory"))
            timeout_flag = os.path.join(output_path, actions.utils.FLAGFOLDER, environment["id"]) + ".timeout"
            fitpath = os.path.join(PROJECT_ROOT, output_path, actions.utils.FLAGFOLDER, environment["id"]) + ".fitness"
            if os.path.exists(timeout_flag):
                logger.debug("Server timeout detected")
                ind.fitness = -360
                with open(fitpath, "w") as fitfile:
                    fitfile.write(str(ind.fitness))

        evaluator.read_fitness(ind)

        # Log the fitness
        #logger.info("[%s] Fitness %s: %s" % (ind.environment_id, str(ind.fitness), str(ind)))

        return ind.environment_id, ind.fitness

    @staticmethod
    def get_args(command):
        """
        Defines required global args for this plugin
        """
        parser = argparse.ArgumentParser(description='ESNI plugin runner', allow_abbrev=False)
        parser.add_argument('--environment-id', action='store', help="ID of the current environment")
        parser.add_argument('--output-directory', action='store', help="Where to output results")
        parser.add_argument('--port', action='store', type=int, help='port to use')
        args, _ = parser.parse_known_args(command)
        return vars(args)
