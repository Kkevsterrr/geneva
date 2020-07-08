"""
HTTP Plugin driver

Overrides the default evaluator plugin handling so we can negotiate a clear port
and track jailed sites to avoid residual censorship.
"""

import argparse
import calendar
import copy
import logging
import os
import random
import socket
import subprocess as sp
import sys
import tempfile
import time
import traceback
import urllib.request

import requests

socket.setdefaulttimeout(1)

import engine
import external_sites
import actions.utils

from plugins.plugin import Plugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASEPATH))
TEST_SITES = copy.deepcopy(external_sites.EXTERNAL_SITES)
JAIL_TRACKER = {}
for site in TEST_SITES:
    JAIL_TRACKER[site] = 0
random.shuffle(TEST_SITES)

GOOD_WORD = "testing"
BAD_WORD = "ultrasurf"
JAIL_TIME = 95


class HTTPPluginRunner(Plugin):
    """
    Defines the HTTP plugin runner.
    """
    name = "http"
    def __init__(self, args):
        """
        Marks this plugin as enabled
        """
        self.enabled = True

    def negotiate_clear_port(self, args, evaluator, environment, logger):
        """
        Since residual censorship might be affecting our IP/port combo
        that was randomly chosen, this method is to find a port on which
        no residual censorship is present. This is done simply by picking a
        port, running the server, running curl to confirm it's accessible,
        and then returning that port.
        """
        while True:
            # Pick a random port if port negotiation is enabled
            if args["disable_port_negotiation"] and not args.get("censor"):
                port = 80
            else:
                port = random.randint(1025, 65000)
                port_bound = True
                while port_bound:
                    try:
                        with socket.socket() as sock:
                            sock.bind(('', port))
                            # if no error thrown, port was unbound and thus we can use it
                            port_bound = False
                    except OSError:
                        # port was bound already, generate new port and try again
                        port = random.randint(1025, 65000)

            # Store that port in the server args
            evaluator.server_args.update({"port": port})
            # Disable the engine so the strategy under test does not interfere with the
            # residual censorship check
            evaluator.server_args.update({"no_engine": True})

            # Start the server on our chosen port
            try:
                http_server = evaluator.start_server(evaluator.server_args, environment, logger)
            except:
                logger.exception("Failed to start server; choosing a new port.")
                continue

            if args["disable_port_negotiation"] or args.get("censor"):
                return http_server, port

            # Test for residual censorship
            dest = "%s:%d" % (evaluator.get_ip(), port)
            logger.debug("Checking for residual censorship at %s" % dest)
            command = "curl -s %s -m 5 -v" % dest
            stdout, stderr = evaluator.remote_exec_cmd(environment["remote"], command, logger, timeout=7)
            for line in stderr:
                if "Connection reset by peer" in line:
                    logger.info("Residual censorship detected on %s." % dest)
                    evaluator.stop_server(environment, http_server)
                    time.sleep(1)
                    continue
                elif "timed out" in line:
                    logger.debug("Connection timed out on %s" % dest)
                    evaluator.stop_server(environment, http_server)
                    raise actions.utils.SkipStrategyException("Strategy broke TCP connection", -400)
            break
        return http_server, port

    def start(self, args, evaluator, environment, ind, logger):
        """
        Runs the plugins
        """
        if args["use_external_sites"]:
            args.update({"external_server" : True})

        forwarder = {}
        if evaluator.act_as_middlebox:
            forwarder["sender_ip"] = args.get("sender_ip")
            forwarder["forward_ip"] = args.get("forward_ip")
            forwarder["routing_ip"] = args.get("routing_ip")

        port = args.get("port", 80)
        tmp_dir = None
        # If we're given a server to start, start it now, but if we're a middlebox, don't run a server
        if evaluator.server_cls and not args.get("external_server") and not evaluator.act_as_middlebox:
            server, port = self.negotiate_clear_port(args, evaluator, environment, logger)

        # Update the port with the given or negotiated port
        evaluator.client_args.update({"port": port})
        site_to_test = evaluator.client_args.get("server", "")

        output_path = os.path.join(PROJECT_ROOT, evaluator.client_args.get("output_directory"))

        with engine.Engine(port, args.get("strategy", ""), server_side=args["server_side"], environment_id=environment["id"], output_directory=output_path, log_level=args.get("log", "debug"), enabled=args["server_side"], forwarder=forwarder) as eng:
            with TestServer(site_to_test, evaluator, environment, logger) as site_to_test:
                evaluator.client_args.update({"server" : site_to_test})
                fitness = evaluator.run_client(evaluator.client_args, environment, logger)

            evaluator.read_fitness(ind)

            # If the engine ran on the server side, ask that it punish fitness
            if args["server_side"]:
                ind.fitness = actions.utils.punish_fitness(fitness, logger, eng)
                actions.utils.write_fitness(ind.fitness, output_path, environment["id"])

        if evaluator.server_cls and not evaluator.args.get("external_server") and not evaluator.act_as_middlebox:
            evaluator.stop_server(environment, server)

        return ind.environment_id, ind.fitness

    @staticmethod
    def get_args(command):
        """
        Defines required global args for all plugins
        """
        parser = argparse.ArgumentParser(description='HTTP plugin runner', allow_abbrev=False)
        parser.add_argument('--disable-port-negotiation', action='store_true', help="disables port negotiation between remote client and local server")
        parser.add_argument('--use-external-sites', action='store_true', help="draw from the pool of external servers (defined in external_sites.py) for testing.")
        parser.add_argument('--environment-id', action='store', help="ID of the current environment")
        parser.add_argument('--output-directory', action='store', help="Where to output results")
        parser.add_argument('--port', action='store', type=int, default=80, help='port to use')
        args, _ = parser.parse_known_args(command)
        return vars(args)


def check_censorship(site, evaluator, environment, logger):
    """
    Make a request to the given site to test if it is censored. Used to test
    a site for residual censorship before using it.
    """
    command = "curl -s %s -m 5" % site
    if environment.get("remote"):
        stdout, stderr = evaluator.remote_exec_cmd(environment["remote"], command, logger, timeout=5)
        for line in stderr:
            if "Connection reset by peer" in line:
                logger.info("Residual censorship detected on %s." % site)
                return False
        return True
    try:
        requests.get(site, allow_redirects=False, timeout=3)
        return True
    except (requests.exceptions.ConnectionError,
            ConnectionResetError,
            urllib.error.URLError,
            requests.exceptions.Timeout,
            Exception) as e:
        logger.error("Could not reach site %s" % site)
        return False


class TestServer():
    """
    Context manager to retrieve a test server from the external server pool.
    """
    def __init__(self, requested_site, evaluator, environment, logger):
        self.requested_site = requested_site
        self.logger = logger
        self.evaluator = evaluator
        self.environment = environment
        self.site_to_test = None

    def __enter__(self):
        """
        Reserves a site for testing for this worker.
        """
        if self.requested_site:
            return self.requested_site

        while True:
            site_to_test = TEST_SITES.pop(0)
            current_seconds = calendar.timegm(time.gmtime())

            # Check if our current time is at least JAIL_TIME away from the last time
            # we tried to use this site.
            if (current_seconds - JAIL_TRACKER[site_to_test]) > JAIL_TIME:
                site_good = False
                self.logger.debug("Checking %s for censorship." % site_to_test)
                site_good = check_censorship(site_to_test, self.evaluator, self.environment, self.logger)

                if site_good:
                    self.logger.debug("Using site %s for testing." % site_to_test)
                    break
                else:
                    self.logger.debug("Residual censorship detected for %s" % site_to_test)

            # If we didn't break, put the site back at the end of the list
            TEST_SITES.append(site_to_test)
            if self.logger:
                self.logger.debug("%s is not yet available to test - only %d seconds have \
                                  transpired since last test - waiting 5 seconds." %
                                  (site_to_test, current_seconds - JAIL_TRACKER[site_to_test]))
            time.sleep(0.1)

        # Store the site we're testing to re-add it to the pool on exit
        self.site_to_test = site_to_test
        return site_to_test

    def __exit__(self, exc_type, exc_value, trace):
        """
        Cleans up and returns the site in testing to the test pool.
        """
        if self.site_to_test:
            self.logger.debug("Returning %s to pool of sites." % self.site_to_test)
            TEST_SITES.append(self.site_to_test)
            JAIL_TRACKER[self.site_to_test] = calendar.timegm(time.gmtime())

        # Pass through exceptions
        if exc_type is not None:
            traceback.print_exception(exc_type, exc_value, trace)
            return False
        return True


# Note that this code is not for debugging and cannot be removed -
# this is how the evaluator runs the client.
if __name__ == "__main__":
    main(vars(get_args()))
