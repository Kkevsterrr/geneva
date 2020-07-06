"""
Geneva Strategy Engine

Given a strategy and a server port, the engine configures NFQueue to capture all traffic
into and out of that port so the strategy can run over the connection.
"""

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import socket
import subprocess
import threading
import time

try:
    import netfilterqueue
except ImportError:
    pass

from scapy.layers.inet import IP
from scapy.utils import wrpcap
from scapy.config import conf

socket.setdefaulttimeout(1)

import layers.packet
import actions.strategy
import actions.utils

BASEPATH = os.path.dirname(os.path.abspath(__file__))


class Engine():
    def __init__(self, server_port,
                       string_strategy,
                       environment_id=None,
                       server_side=False,
                       output_directory="trials",
                       log_level="info",
                       enabled=True,
                       in_queue_num=None,
                       out_queue_num=None,
                       forwarder=None,
                       save_seen_packets=True,
                       demo_mode=False):
        """
        Args:
            server_port (int): The port the engine will monitor
            string_strategy (str): String representation of strategy DNA to apply to the network
            environment_id (str, None): ID of the given strategy
            server_side (bool, False): Whether or not the engine is running on the server side of the connection
            output_directory (str, 'trials'): The path logs and packet captures should be written to
            enabled (bool, True): whether or not the engine should be started (used for conditional context managers)
            in_queue_num (int, None): override the netfilterqueue number used for inbound packets. Used for running multiple instances of the engine at the same time. Defaults to None.
            out_queue_num (int, None): override the netfilterqueue number used for outbound packets. Used for running multiple instances of the engine at the same time. Defaults to None.
            save_seen_packets (bool, True): whether or not the engine should record and save packets it sees while running. Defaults to True, but it is recommended this be disabled on higher throughput systems.
            demo_mode (bool, False): whether to replace IPs in log messages with random IPs to hide sensitive IP addresses.
        """
        self.server_port = server_port
        # whether the engine is running on the server or client side.
        # this affects which direction each out/in tree is attached to the
        # source and destination port.
        self.server_side = server_side
        self.overhead = 0
        self.seen_packets = []
        self.environment_id = environment_id
        self.forwarder = forwarder
        self.save_seen_packets = save_seen_packets
        if forwarder:
            self.sender_ip = forwarder["sender_ip"]
            self.routing_ip = forwarder["routing_ip"]
            self.forward_ip = forwarder["forward_ip"]

        # Set up the directory and ID for logging
        if not output_directory:
            self.output_directory = "trials"
        else:
            self.output_directory = output_directory
        actions.utils.setup_dirs(self.output_directory)
        if not environment_id:
            self.environment_id = actions.utils.get_id()

        # Set up a logger
        self.logger = actions.utils.get_logger(BASEPATH,
                                               self.output_directory,
                                               __name__,
                                               "engine",
                                               self.environment_id,
                                               log_level=log_level,
                                               demo_mode=demo_mode)
        # Warn if these are not provided
        if not environment_id:
            self.logger.warning("No environment ID given, one has been generated (%s)", self.environment_id)
        if not output_directory:
            self.logger.warning("No output directory specified, using the default (%s)" % self.output_directory)

        # Used for conditional context manager usage
        self.enabled = enabled

        # Parse the given strategy
        self.strategy = actions.utils.parse(string_strategy, self.logger)

        # Setup variables used by the NFQueue system
        self.in_queue_num = in_queue_num or 1
        self.out_queue_num = out_queue_num or self.in_queue_num + 1
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
        engine if enabled.
        """
        if self.enabled:
            self.initialize_nfqueue()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """
        Allows the engine to be used as a context manager; simply stops the engine
        if enabled.
        """
        if self.enabled:
            self.shutdown_nfqueue()

    def do_nat(self, packet):
        """
        NATs packet: changes the sources and destination IP if it matches the
        configured route, and clears the checksums for recalculating

        Args:
            packet (layers.packet.Packet): packet to modify before sending

        Returns:
            layers.packet.Packet: the modified packet
        """
        if packet["IP"].src == self.sender_ip:
            packet["IP"].dst = self.forward_ip
            packet["IP"].src = self.routing_ip
            del packet["TCP"].chksum
            del packet["IP"].chksum
        elif packet["IP"].src == self.forward_ip:
            packet["IP"].dst = self.sender_ip
            packet["IP"].src = self.routing_ip
            del packet["TCP"].chksum
            del packet["IP"].chksum
        return packet

    def mysend(self, packet):
        """
        Helper scapy sending method. Expects a Geneva Packet input.
        """
        try:
            if self.forwarder:
                self.logger.debug("NAT-ing packet.")
                packet = self.do_nat(packet)
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
                # run_socket can raise an OSError on shutdown for some builds of netfilterqueue
                except (socket.timeout, OSError):
                    pass
        except Exception:
            self.logger.exception("Exception out of run_nfqueue() (direction=%s)", direction)

    def configure_iptables(self, remove=False):
        """
        Handles setting up ipables for this run
        """
        self.logger.debug("Configuring iptables rules")

        # Switch source and destination ports if this evaluator is to run from the server side
        port1, port2 = "sport", "dport"
        if not self.server_side:
            port1, port2 = "dport", "sport"

        out_chain = "OUTPUT"
        in_chain = "INPUT"

        # Switch whether the command should add or delete the rules
        add_or_remove = "A"
        if remove:
            add_or_remove = "D"
        cmds = []
        for proto in ["tcp", "udp"]:
            cmds += ["iptables -%s %s -p %s --%s %d -j NFQUEUE --queue-num %d" %
                    (add_or_remove, out_chain, proto, port1, self.server_port, self.out_queue_num),
                    "iptables -%s %s -p %s --%s %d -j NFQUEUE --queue-num %d" %
                    (add_or_remove, in_chain, proto, port2, self.server_port, self.in_queue_num)]
            # If this machine is acting as a middlebox, we need to add the same rules again
            # in the opposite direction so that we can pass packets back and forth
            if self.forwarder:
                cmds += ["iptables -%s %s -p %s --%s %d -j NFQUEUE --queue-num %d" %
                    (add_or_remove, out_chain, proto, port2, self.server_port, self.out_queue_num),
                    "iptables -%s %s -p %s --%s %d -j NFQUEUE --queue-num %d" %
                    (add_or_remove, in_chain, proto, port1, self.server_port, self.in_queue_num)]

        for cmd in cmds:
            self.logger.debug(cmd)
            # If we're logging at debug mode, keep stderr/stdout piped to us
            # Otherwise, pipe them both to DEVNULL
            if actions.utils.get_console_log_level() == "debug":
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
        self.out_nfqueue.bind(self.out_queue_num, self.out_callback)
        self.in_nfqueue.bind(self.in_queue_num, self.in_callback)
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
        self.socket.close()
        self.out_nfqueue_socket.close()
        self.in_nfqueue_socket.close()

        packets_path = os.path.join(BASEPATH,
                                    self.output_directory,
                                    "packets",
                                    "original_%s.pcap" % self.environment_id)

        # Write to disk the original packets we captured
        if self.save_seen_packets:
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

        packet = layers.packet.Packet(IP(nfpacket.get_payload()))
        self.logger.debug("Received outbound packet %s", str(packet))

        # Record this packet for a .pacp later
        if self.save_seen_packets:
            self.seen_packets.append(packet)

        # Drop the packet in NFQueue so the strategy can handle it
        nfpacket.drop()

        self.handle_packet(packet)

    def handle_packet(self, packet):
        """
        Handles processing an outbound packet through the engine.
        """
        packets_to_send = self.strategy.act_on_packet(packet, self.logger, direction="out")
        if packets_to_send:
            self.overhead += (len(packets_to_send) - 1)

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
        packet = layers.packet.Packet(IP(nfpacket.get_payload()))

        if self.save_seen_packets:
            self.seen_packets.append(packet)

        self.logger.debug("Received packet: %s", str(packet))

        # Run the given strategy
        packets = self.strategy.act_on_packet(packet, self.logger, direction="in")

        # GFW will send RA packets to disrupt a TCP stream
        if packet.haslayer("TCP") and packet.get("TCP", "flags") == "RA":
            self.censorship_detected = True

        # Branching is disabled for the in direction, so we can only ever get
        # back 1 or 0 packets. If zero, drop the packet.
        if not packets:
            nfpacket.drop()
            return

        if self.forwarder:
            nfpacket.drop()
            self.handle_packet(packet)
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
    parser.add_argument('--environment-id', action='store', help="ID of the current strategy under test")
    parser.add_argument('--sender-ip', action='store', help="IP address of sending machine, used for NAT")
    parser.add_argument('--routing-ip', action='store', help="Public IP of this machine, used for NAT")
    parser.add_argument('--forward-ip', action='store', help="IP address to forward traffic to")
    parser.add_argument('--strategy', action='store', help="Strategy to deploy")
    parser.add_argument('--output-directory', default="trials", action='store', help="Where to output logs, captures, and results. Defaults to trials/.")
    parser.add_argument('--forward', action='store_true', help='Enable if this is forwarding traffic')
    parser.add_argument('--server-side', action='store_true', help='Enable if this is running on the server side')
    parser.add_argument('--log', action='store', default="debug",
                        choices=("debug", "info", "warning", "critical", "error"),
                        help="Sets the log level")
    parser.add_argument('--no-save-packets', action='store_false', help='Disables recording captured packets')
    parser.add_argument("--in-queue-num", action="store", help="NfQueue number for incoming packets", default=1, type=int)
    parser.add_argument("--out-queue-num", action="store", help="NfQueue number for outgoing packets", default=None, type=int)
    parser.add_argument("--demo-mode", action='store_true', help="Replaces all IPs with dummy IPs in log messages so as not to reveal sensitive IP addresses")

    args = parser.parse_args()
    return args


def main(args):
    """
    Kicks off the engine with the given arguments.
    """
    try:
        nat_config = {}
        if args.get("sender_ip") and args.get("routing_ip") and args.get("forward_ip"):
            nat_config = {"sender_ip" : args["sender_ip"],
                          "routing_ip" : args["routing_ip"],
                          "forward_ip" : args["forward_ip"]}

        eng = Engine(args["server_port"],
                     args["strategy"],
                     environment_id=args["environment_id"],
                     server_side=args["server_side"],
                     output_directory=args["output_directory"],
                     forwarder=nat_config,
                     log_level=args["log"],
                     in_queue_num=args["in_queue_num"],
                     out_queue_num=args["out_queue_num"],
                     save_seen_packets=args["no_save_packets"],
                     demo_mode=args["demo_mode"])
        eng.initialize_nfqueue()
        while True:
            time.sleep(0.5)
    finally:
        eng.shutdown_nfqueue()


if __name__ == "__main__":
    main(vars(get_args()))
