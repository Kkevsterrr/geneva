"""
Client

Run by the evaluator, tries to make a GET request to a given server
"""

import argparse
import logging
import os
import random
import socket
import sys
import time
import traceback
import urllib.request

import dns.resolver
import requests

import actions.utils
from plugins.plugin_client import ClientPlugin


class DNSClient(ClientPlugin):
    """
    Defines the DNS client.
    """
    name = "dns"

    def __init__(self, args):
        """
        Initializes the DNS client.
        """
        ClientPlugin.__init__(self)
        self.args = args

    @staticmethod
    def get_args(command):
        """
        Defines required args for this plugin
        """
        super_args = ClientPlugin.get_args(command)
        parser = argparse.ArgumentParser(description='DNS Client')

        parser.add_argument('--use-tcp', action='store_true', help='leverage TCP for this plugin')
        parser.add_argument('--dns-server', action='store', default="8.8.8.8", help='domain server to connect to')
        parser.add_argument('--query', action='store', default="facebook.com", help='censored domain to query')
        parser.add_argument('--timeout', action='store', default="3", type=int, help='how long in seconds the client should wait for a response')
        parser.add_argument('--port', action='store', default="53", type=int, help='port the DNS server is running on (must be 53)')

        args, _ = parser.parse_known_args(command)
        args = vars(args)

        super_args.update(args)
        return super_args

    def run(self, args, logger, engine=None):
        """
        Try to make a forbidden DNS query.
        """
        fitness = 0
        to_lookup = args.get("query", "facebook.com")
        dns_server = args.get("dns_server", "8.8.8.8")
        use_tcp = args.get("use_tcp", False)
        assert dns_server, "Cannot launch DNS test with no DNS server"
        assert to_lookup, "Cannot launch DNS test with no server to query"
        fitness = -1000
        try:
            fitness = self.dns_test(to_lookup, dns_server, args["output_directory"], args["environment_id"], logger, timeout=args.get("timeout", 3), use_tcp=use_tcp)
        except Exception:
            logger.exception("Exception caught in DNS test to resolver %s.", dns_server)
            fitness += -100

        # When performing a DNS test, a timeout is indistinguishable from
        # a reset, which means we can't tell if the strategy broke the packet
        # stream, or if the censor caught us. Strategies that break the stream
        # should be punished more harshly, so raise the fitness slightly
        # if the engine detected censorship for failed DNS tests.
        if use_tcp and engine and engine.censorship_detected and fitness < 0:
            fitness += 10
        return fitness * 4

    def dns_test(self, to_lookup, dns_server, output_dir, environment_id, logger, timeout=3, use_tcp=False):
        """
        Makes a DNS query to a given censored domain.
        """
        # Make the path an absolute path
        if not output_dir.startswith("/"):
            output_dir = os.path.join(actions.utils.PROJECT_ROOT, output_dir)

        resolver = dns.resolver.Resolver()
        protocol = "UDP"
        if use_tcp:
            protocol = "TCP"

        logger.debug("Querying %s to DNS server %s over %s" % (to_lookup, dns_server, protocol))
        resolver.nameservers = [dns_server]
        # Setup the timeout and lifetime for this resolver
        resolver.timeout = timeout
        resolver.lifetime = 3

        try:
            answer = resolver.query(to_lookup, "A", tcp=use_tcp)[0]
            logger.debug("Got IP address: %s" % answer)
            # At this point, we've been given an IP address by the DNS resolver, but we don't
            # yet know if this IP address is a bogus injected response, or legitimate. Further,
            # because we are likely running this code from within a censored regime which might
            # employ secondary censorship at the IP level, we cannot check if this IP is legit
            # here. Instead, we write it out to a file for the evaluator to extract and check for us.
            with open(os.path.join(output_dir, "flags", environment_id)+".dnsresult", "w") as dnsfile:
                dnsfile.write(str(answer))
            # For now, set fitness to a positive metric, though the evaluator will lower it if
            # the IP address we were given was bogus.
            fitness = 100
        except dns.exception.Timeout:
            logger.error("DNS query timed out.")
            fitness = -100
        except dns.resolver.NoNameservers:
            logger.error("DNS server failed to respond")
            fitness = -100

        return fitness
