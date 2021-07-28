"""
Amplification Plugin driver

Overrides the default evaluator plugin handling so we can optimize testing many strategies at once,
since we will not use the engine.
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
import tqdm
import urllib.request

import requests
from scapy.all import *

import actions.utils
from plugins.plugin import Plugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASEPATH))


def get_open_sport(strategy_ports, logger):
    """
    Returns a source port that is not currently being used.
    """
    while True:
        # Pick a port somewhere between 10,000 and 60,000
        sport = random.randint(10000, 60000)
        # If the source port has already been used, try to find a different one
        if sport in strategy_ports:
            continue

        # Bind TCP socket
        try:
            with socket.socket() as sock:
                # If we can bind, nothing is listening
                sock.bind(('', sport))
                break
        except OSError:
            logger.debug("Port %d is in use, picking another" % sport)
            continue
    logger.debug("Using source port %d" % sport)
    return sport


class AmplificationPluginRunner(Plugin):
    """
    Defines the amplification plugin runner.
    """
    name = "amplification"
    override_evaluation = True

    def __init__(self, args):
        """
        Marks this plugin as enabled
        """
        self.enabled = True
        self.logger = None
        self.strategy_ports = {}
        self.responses = {}
        self.sent_sizes = {}
        self.disregard_empty = False

    def handle_packet(self, packet):
        """
        Called by scapy when a matching inbound packet is seen.
        """
        strategy_port = packet["TCP"].dport
        # If not to any strategy, not from us
        if strategy_port not in self.strategy_ports:
            return

        if not packet.haslayer("TCP"):
            return

        if self.disregard_empty and not packet["TCP"].payload:
            return

        self.logger.debug("[%s] Received packet (%d): %s / %s", self.strategy_ports[strategy_port].environment_id, len(bytes(packet)), packet.summary(), packet["TCP"].payload)

        if strategy_port not in self.responses:
            self.responses[strategy_port] = []

        self.responses[strategy_port].append(packet)

    def evaluate(self, args, evaluator, population, logger):
        """
        Runs the plugins
        """
        self.logger = logger
        self.disregard_empty = args["disregard_empty"]
        # Clear the responses for the start of this generation
        self.responses.clear()

        dport = int(args.get("port", 7))
        logger.debug("Using port %d" % dport)
        site = args["site"]
        dst = args["dst"]

        payload = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % site
        payload = payload.encode()

        # Create a sniffer
        logger.debug("Starting sniffer")
        sniffer = AsyncSniffer(filter="tcp and src port %d" % dport, prn=self.handle_packet, store=False)
        sniffer.start()

        # Maps source ports to strategies
        self.strategy_ports = {}
        self.sent_sizes = {}
        for ind in tqdm.tqdm(population, leave=False, disable=(actions.utils.CONSOLE_LOG_LEVEL == "debug")):
            sport = get_open_sport(self.strategy_ports, logger)
            # Reserve this source port for this strategy
            self.strategy_ports[sport] = ind
            seq = int(RandInt())
            ack = int(RandInt())
            packets = [
                IP(dst=dst)/TCP(sport=sport, dport=dport, flags="S", ack=0, seq=seq),
                IP(dst=dst)/TCP(sport=sport, dport=dport, flags="A", ack=ack, seq=seq+1),
                IP(dst=dst)/TCP(sport=sport, dport=dport, flags="PA", ack=ack, seq=seq+1)/Raw(payload)
            ]
            packets = [actions.packet.Packet(packet) for packet in packets]

            packets_to_send = []
            try:
                for packet in packets:
                    # Run the strategy on the packet
                    packets_to_send += ind.act_on_packet(packet, logger)
            except Exception:
                logger.exception("Error running strategy")
                ind.fitness = -1000
                continue

            # If the strategy sends no packets, punish and continue
            if not packets_to_send:
                ind.fitness = -1000
                continue

            for packet in packets_to_send:
                # Record the size we're about to send
                if sport not in self.sent_sizes:
                    self.sent_sizes[sport] = 0
                self.sent_sizes[sport] += len(bytes(packet.packet))
            logger.debug("About to send %d bytes" % self.sent_sizes[sport])

            for packet in packets_to_send:
                if packet.sleep:
                    time.sleep(packet.sleep)

                self.logger.debug("Sending packet (%d) %s", len(bytes(packet)), str(packet))
                # Send the packet
                send(packet.packet, verbose=False)

            # Sleep the requested milliseconds between generations
            time.sleep(args["sleep"]/1000)

        logger.info("Sleeping %d cooldown seconds to wait for packets to come in" % args["cooldown"])
        time.sleep(args["cooldown"])

        logger.debug("Stopping sniffer")
        sniffer.stop()

        # Zero out the fitnesses for strategies that do not get responses
        for port in self.strategy_ports:
            ind = self.strategy_ports[port]
            if ind.fitness != -1000:
                ind.fitness = 0
                if port in self.responses:
                    for response in self.responses[port]:
                        ind.fitness += len(bytes(response))

                    ind.fitness = round(ind.fitness / self.sent_sizes[port], 3)
                    self.logger.debug("[%s] Fitness %s: %s" % (ind.environment_id, ind.fitness, str(ind)))

                ind.fitness = actions.utils.punish_unused(ind.fitness, logger, ind)
            logger.debug("[%s] Fitness: %s: %s" % (ind.environment_id, ind.fitness, str(ind)))

        self.strategy_ports.clear()
        self.responses.clear()
        return population

    @staticmethod
    def get_args(command):
        """
        Defines required args for this plugin
        """
        parser = argparse.ArgumentParser(description='Amplification plugin runner', allow_abbrev=False)
        parser.add_argument('--output-directory', action='store', help="Where to output results")
        parser.add_argument('--sleep', action='store', type=int, default=500, help='milliseconds to sleep between each strategy')
        parser.add_argument('--port', action='store', type=int, default=7, help='port to use')
        parser.add_argument('--dst', action='store', help='IP to use')
        parser.add_argument('--runs', action='store', help='Runs per strategy')
        parser.add_argument('--site', action='store', default="pornhub.com", help='Site to include in the HTTP GET request')
        parser.add_argument('--disregard-empty', action='store_true', help='Disregard packets without payloads (RSTs)')
        parser.add_argument('--cooldown', action='store', type=int, default=8, help='amount of time after the last packet is sent to collect packets')
        args, _ = parser.parse_known_args(command)
        return vars(args)
