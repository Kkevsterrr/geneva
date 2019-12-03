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

from scapy.layers.inet import IP
from scapy.utils import wrpcap
from scapy.config import conf
from scapy.all import send, Raw

import pydivert #TODO
from pydivert.consts import Direction

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
        
        # Instantialize a PyDivert channel, which we will use to redirect packets
        self.divert = None
        self.divert_thread = None
        self.divert_thread_started = False

        self.censorship_detected = False
        # Specifically define an L3Socket to send our packets. This is an optimization
        # for scapy to send packets more quickly than using just send(), as under the hood
        # send() creates and then destroys a socket each time, imparting a large amount
        # of overhead.
        self.socket = conf.L3socket(iface=actions.utils.get_interface()) # TODO: FIX

    def initialize_divert(self):
        """
        Initializes Divert such that all packets for the connection will come through us
        """

        self.logger.debug("Engine created with strategy %s (ID %s) to port %s",
                          str(self.strategy).strip(), self.environment_id, self.server_port)

        self.logger.debug("Initializing Divert")

        self.divert = pydivert.WinDivert("tcp.DstPort == %d || tcp.SrcPort == %d" % (int(self.server_port), int(self.server_port)))
        self.divert.open()
        self.divert_thread = threading.Thread(target=self.run_divert)
        self.divert_thread.start()

        maxwait = 100 # 100 time steps of 0.01 seconds for a max wait of 10 seconds
        i = 0
        # Give Divert time to startup, since it's running in background threads
        # Block the main thread until this is done
        while not self.divert_thread_started and i < maxwait:
            time.sleep(0.1)
            i += 1
        self.logger.debug("Divert Initialized after %d", int(i))

        return

    def shutdown_divert(self):
        """
        Closes the divert connection
        """
        if self.divert:
            self.divert.close()
            self.divert = None
            
        return

    def run_divert(self):
        """ 
        Runs actions on packets
        """
        if self.divert:
            self.divert_thread_started = True

        for packet in self.divert:
            if packet.is_outbound:
                # Send to outbound action tree, if any
                self.handle_outbound_packet(packet)

            elif packet.is_inbound:
                # Send to inbound action tree, if any
                self.handle_inbound_packet(packet)

        return

    def __enter__(self):
        """
        TODO
        """
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """
        TODO
        """
        return

    def mysend(self, packet, dir):
        """
        Helper scapy sending method. Expects a Geneva Packet input.
        """
        try:
            self.logger.debug("Sending packet %s", str(packet))

            #Convert packet to pydivert

            #print(bytes(Raw(packet.packet)))
            #print(packet.packet)
            pack = bytes(packet.packet)
            pack2 = bytearray(pack)
            #print(pack2[0])
            #send(IP(packet.packet), iface="Wi-Fi")
            #pack = bytearray(bytes(Raw(packet.packet)), "UTF-8")
            #print(pack)
            self.divert.send(pydivert.Packet(memoryview(pack2), (12, 0), dir), recalculate_checksum=False) # TODO: FIX

        except Exception:
            self.logger.exception("Error in engine mysend.")
    
    def handle_outbound_packet(self, divert_packet):
        """
        Handles outbound packets by sending them the the strategy
        """
        #print(divert_packet)
        packet = actions.packet.Packet(IP(divert_packet.raw.tobytes()))
        #print(packet.show2())
        self.logger.debug("Received outbound packet %s", str(packet))

        # Record this packet for a .pcap later
        self.seen_packets.append(packet)

        packets_to_send = self.strategy.act_on_packet(packet, self.logger, direction="out")

        # Send all of the packets we've collected to send
        for out_packet in packets_to_send:
            self.mysend(out_packet, Direction.OUTBOUND)        

    def handle_inbound_packet(self, divert_packet):
        """
        Handles inbound packets. Process the packet and forward it to the strategy if needed.
        """

        packet = actions.packet.Packet(IP(divert_packet.raw.tobytes()))

        self.seen_packets.append(packet)

        self.logger.debug("Received packet: %s", str(packet))

        # Run the given strategy
        packets = self.strategy.act_on_packet(packet, self.logger, direction="in")

        # GFW will send RA packets to disrupt a TCP stream
        if packet.haslayer("TCP") and packet.get("TCP", "flags") == "RA":
            self.logger.debug("Detected GFW censorship - strategy failed.")
            self.censorship_detected = True

        # Branching is disabled for the in direction, so we can only ever get
        # back 1 or 0 packets. If zero, return and do not send packet. 
        if not packets:
            return

        # If the strategy requested us to sleep before accepting on this packet, do so here
        if packets[0].sleep:
            time.sleep(packets[0].sleep)

        # Accept the modified packet
        self.mysend(packets[0], Direction.INBOUND)


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
        eng.initialize_divert()
        while True:
            time.sleep(0.5)
    finally:
        eng.shutdown_divert()


if __name__ == "__main__":
    main(vars(get_args()))
