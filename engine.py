"""
Engine

Given a strategy and a server port, the engine configures NFQueue
so the strategy can run on the underlying connection.
"""

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import socket
import subprocess
import threading
import time

import netfilterqueue

from scapy.layers.inet import IP
from scapy.utils import wrpcap
from scapy.config import conf

socket.setdefaulttimeout(1)

import actions.packet
import actions.strategy
import actions.utils

BASEPATH = os.path.dirname(os.path.abspath(__file__))


class Engine():
    def __init__(self, server_port, string_strategy, environment_id=None, output_directory="trials", log_level="info"):
        self.server_port = server_port
        self.seen_packets = []
        # Set up the directory and ID for logging
        if not output_directory:
            output_directory = "trials"
        actions.utils.setup_dirs(output_directory)
        if not environment_id:
            environment_id = actions.utils.get_id()

        self.environment_id = environment_id
        # Set up a logger
        self.logger = actions.utils.get_logger(BASEPATH,
                                               output_directory,
                                               __name__,
                                               "engine",
                                               environment_id,
                                               log_level=log_level)
        self.output_directory = output_directory

        # Used for conditional context manager usage
        self.strategy = actions.utils.parse(string_strategy, self.logger)
        # Setup variables used by the NFQueue system
        self.out_nfqueue_started = False
        self.in_nfqueue_started = False
        self.running_nfqueue = False
        self.out_nfqueue = None
        self.in_nfqueue = None
        self.out_nfqueue_socket = None
        self.in_nfqueue_socket = None
        self.out_nfqueue_thread = None
        self.in_nfqueue_thread = None
        self.censorship_detected = False
        # Specifically define an L3Socket to send our packets. This is an optimization
        # for scapy to send packets more quickly than using just send(), as under the hood
        # send() creates and then destroys a socket each time, imparting a large amount
        # of overhead.
        self.socket = conf.L3socket(iface=actions.utils.get_interface())

    def __enter__(self):
        """
        Allows the engine to be used as a context manager; simply launches the
        engine.
        """
        self.initialize_nfqueue()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """
        Allows the engine to be used as a context manager; simply stops the engine
        """
        self.shutdown_nfqueue()

    def mysend(self, packet):
        """
        Helper scapy sending method. Expects a Geneva Packet input.
        """
        try:
            self.logger.debug("Sending packet %s", str(packet))
            self.socket.send(packet.packet)
        except Exception:
            self.logger.exception("Error in engine mysend.")

    def delayed_send(self, packet, delay):
        """
        Method to be started by a thread to delay the sending of a packet without blocking the main thread.
        """
        self.logger.debug("Sleeping for %f seconds." % delay)
        time.sleep(delay)
        self.mysend(packet)

    def run_nfqueue(self, nfqueue, nfqueue_socket, direction):
        """
        Handles running the outbound nfqueue socket with the socket timeout.
        """
        try:
            while self.running_nfqueue:
                try:
                    if direction == "out":
                        self.out_nfqueue_started = True
                    else:
                        self.in_nfqueue_started = True

                    nfqueue.run_socket(nfqueue_socket)
                except socket.timeout:
                    pass
        except Exception:
            self.logger.exception("Exception out of run_nfqueue() (direction=%s)", direction)

    def configure_iptables(self, remove=False):
        """
        Handles setting up ipables for this run
        """
        self.logger.debug("Configuring iptables rules")

        port1, port2 = "dport", "sport"

        out_chain = "OUTPUT"
        in_chain = "INPUT"

        # Switch whether the command should add or delete the rules
        add_or_remove = "A"
        if remove:
            add_or_remove = "D"
        cmds = []
        for proto in ["tcp", "udp"]:
            cmds += ["iptables -%s %s -p %s --%s %d -j NFQUEUE --queue-num 1" %
                     (add_or_remove, out_chain, proto, port1, self.server_port),
                     "iptables -%s %s -p %s --%s %d -j NFQUEUE --queue-num 2" %
                     (add_or_remove, in_chain, proto, port2, self.server_port)]

        for cmd in cmds:
            self.logger.debug(cmd)
            # If we're logging at DEBUG mode, keep stderr/stdout piped to us
            # Otherwise, pipe them both to DEVNULL
            if actions.utils.get_console_log_level() == logging.DEBUG:
                subprocess.check_call(cmd.split(), timeout=60)
            else:
                subprocess.check_call(cmd.split(), stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=60)
        return cmds

    def initialize_nfqueue(self):
        """
        Initializes the nfqueue for input and output forests.
        """
        self.logger.debug("Engine created with strategy %s (ID %s) to port %s",
                          str(self.strategy).strip(), self.environment_id, self.server_port)
        self.configure_iptables()

        self.out_nfqueue_started = False
        self.in_nfqueue_started = False
        self.running_nfqueue = True
        # Create our NFQueues
        self.out_nfqueue = netfilterqueue.NetfilterQueue()
        self.in_nfqueue = netfilterqueue.NetfilterQueue()
        # Bind them
        self.out_nfqueue.bind(1, self.out_callback)
        self.in_nfqueue.bind(2, self.in_callback)
        # Create our nfqueue sockets to allow for non-blocking usage
        self.out_nfqueue_socket = socket.fromfd(self.out_nfqueue.get_fd(),
                                                socket.AF_UNIX,
                                                socket.SOCK_STREAM)
        self.in_nfqueue_socket = socket.fromfd(self.in_nfqueue.get_fd(),
                                               socket.AF_UNIX,
                                               socket.SOCK_STREAM)
        # Create our handling threads for packets
        self.out_nfqueue_thread = threading.Thread(target=self.run_nfqueue,
                                                   args=(self.out_nfqueue, self.out_nfqueue_socket, "out"))

        self.in_nfqueue_thread = threading.Thread(target=self.run_nfqueue,
                                                  args=(self.in_nfqueue, self.in_nfqueue_socket, "in"))
        # Start each thread
        self.in_nfqueue_thread.start()
        self.out_nfqueue_thread.start()

        maxwait = 100 # 100 time steps of 0.01 seconds for a max wait of 10 seconds
        i = 0
        # Give NFQueue time to startup, since it's running in background threads
        # Block the main thread until this is done
        while (not self.in_nfqueue_started or not self.out_nfqueue_started) and i < maxwait:
            time.sleep(0.1)
            i += 1
        self.logger.debug("NFQueue Initialized after %d", int(i))

    def shutdown_nfqueue(self):
        """
        Shutdown nfqueue.
        """
        self.logger.debug("Shutting down NFQueue")
        self.out_nfqueue_started = False
        self.in_nfqueue_started = False
        self.running_nfqueue = False
        # Give the handlers two seconds to leave the callbacks before we forcibly unbind
        # the queues.
        time.sleep(2)
        if self.in_nfqueue:
            self.in_nfqueue.unbind()
        if self.out_nfqueue:
            self.out_nfqueue.unbind()
        self.configure_iptables(remove=True)

        packets_path = os.path.join(BASEPATH,
                                    self.output_directory,
                                    "packets",
                                    "original_%s.pcap" % self.environment_id)

        # Write to disk the original packets we captured
        wrpcap(packets_path, [p.packet for p in self.seen_packets])

        # If the engine exits before it initializes for any reason, these threads may not be set
        # Only join them if they are defined
        if self.out_nfqueue_thread:
            self.out_nfqueue_thread.join()
        if self.in_nfqueue_thread:
            self.in_nfqueue_thread.join()

        # Shutdown the logger
        actions.utils.close_logger(self.logger)

    def out_callback(self, nfpacket):
        """
        Callback bound to the outgoing nfqueue rule to run the outbound strategy.
        """
        if not self.running_nfqueue:
            return

        packet = actions.packet.Packet(IP(nfpacket.get_payload()))
        self.logger.debug("Received outbound packet %s", str(packet))

        # Record this packet for a .pacp later
        self.seen_packets.append(packet)

        # Drop the packet in NFQueue so the strategy can handle it
        nfpacket.drop()

        self.handle_packet(packet)

    def handle_packet(self, packet):
        """
        Handles processing an outbound packet through the engine.
        """
        packets_to_send = self.strategy.act_on_packet(packet, self.logger, direction="out")

        # Send all of the packets we've collected to send
        for out_packet in packets_to_send:
            # If the strategy requested us to sleep before sending this packet, do so here
            if out_packet.sleep:
                # We can't block the main sending thread, so instead spin off a new thread to handle sleeping
                threading.Thread(target=self.delayed_send, args=(out_packet, out_packet.sleep)).start()
            else:
                self.mysend(out_packet)

    def in_callback(self, nfpacket):
        """
        Callback bound to the incoming nfqueue rule. Since we can't
        manually send packets to ourself, process the given packet here.
        """
        if not self.running_nfqueue:
            return
        packet = actions.packet.Packet(IP(nfpacket.get_payload()))

        self.seen_packets.append(packet)

        self.logger.debug("Received packet: %s", str(packet))

        # Run the given strategy
        packets = self.strategy.act_on_packet(packet, self.logger, direction="in")

        # GFW will send RA packets to disrupt a TCP stream
        if packet.haslayer("TCP") and packet.get("TCP", "flags") == "RA":
            self.logger.debug("Detected GFW censorship - strategy failed.")
            self.censorship_detected = True

        # Branching is disabled for the in direction, so we can only ever get
        # back 1 or 0 packets. If zero, drop the packet.
        if not packets:
            nfpacket.drop()
            return

        # Otherwise, overwrite this packet with the packet the action trees gave back
        nfpacket.set_payload(bytes(packets[0]))

        # If the strategy requested us to sleep before accepting on this packet, do so here
        if packets[0].sleep:
            time.sleep(packets[0].sleep)

        # Accept the modified packet
        nfpacket.accept()


def get_args():
    """
    Sets up argparse and collects arguments.
    """
    parser = argparse.ArgumentParser(description='The engine that runs a given strategy.')
    parser.add_argument('--server-port', type=int, action='store', required=True)
    parser.add_argument('--environment-id', action='store', help="ID of the current strategy under test. If not provided, one will be generated.")
    parser.add_argument('--strategy', action='store', help="Strategy to deploy")
    parser.add_argument('--output-directory', default="trials", action='store', help="Where to output logs, captures, and results. Defaults to trials/.")
    parser.add_argument('--log', action='store', default="debug",
                        choices=("debug", "info", "warning", "critical", "error"),
                        help="Sets the log level")

    args = parser.parse_args()
    return args


def main(args):
    """
    Kicks off the engine with the given arguments.
    """
    try:
        eng = Engine(args["server_port"],
                     args["strategy"],
                     environment_id=args.get("environment_id"),
                     output_directory = args.get("output_directory"),
                     log_level=args["log"])
        eng.initialize_nfqueue()
        while True:
            time.sleep(0.5)
    finally:
        eng.shutdown_nfqueue()


if __name__ == "__main__":
    main(vars(get_args()))
