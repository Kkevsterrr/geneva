"""
Code influenced from:
- https://github.com/emileaben/scapy-dns-ninja/blob/master/dns-ninja-server.py
- https://thepacketgeek.com/scapy-p-09-scapy-and-dns/

"""

import argparse

# DNS Modules
import dns.zone
from dns.exception import DNSException

# Scapy modules
from scapy.layers.dns import *
from scapy.all import send

# Debugging
from pprint import pformat

# TLDs
from tld import get_fld

import inspect
import random
import os
import sys

from plugins.plugin_server import ServerPlugin

# Listener - NetfilterQueue
try:
    from netfilterqueue import NetfilterQueue
except ImportError:
    print("ERROR: Failed to import netfilerqueue.")

# Listener - Socket
import socket

BASEPATH = os.path.dirname(os.path.abspath(__file__))

# Utils
import datetime
import actions.utils
import logging

# Default values
INTERFACE = "lo0"
LISTENER = "socket_UDP"
PORT = 53
DNS_RESOLVER = "1.1.1.1"
ZONES_DIR = "zones/"
LOG_LEVEL = "info"


class DNSServer(ServerPlugin):
    """
    Purpose: Handle incoming DNS queries and respond with resource records defined in a zone configuration file (if
    exists for that domain) or respond with the answer given by a DNS resolver

    Features:
    - Loads zone configuration files (--zones-dir)
    - Forwards DNS requests to a DNS resolver for domains that it does not know the answer to (--dns-resolver)
    - DNS forwarding can be disabled with (--no-forwarding)
    - Can act as the authority server for all DNS responses

    Zones:
    - Support for A, MX, NS, TXT and CNAME
    - Other records may be automatically supported through the default action (no special case)
    - Only the first string per TXT record will be retrieved to avoid duplicated quotes

    Logging:
    - Logs are created for each run and saved in the directory specified (--log-dir)
    - Logs can be disabled with (--no-log)

    Python Test: tests/test_dns_server.py
    """
    name = "dns"
    netfilter_queue = 'netfilterqueue'
    socket_UDP = 'socket_UDP'
    socket_TCP = 'socket_TCP'

    def __init__(self, args, logger=None):
        """
        Initializes the DNS Server.
        """
        ServerPlugin.__init__(self)
        self.nfqueue = None
        self.nfqueue_num = None
        self.sock = None
        self.running = False
        self.zones = {}
        self.packet_counter = 0
        self.logger = logger

        if not args:
            return

        # Arguments
        self.interface = args["interface"]
        self.listener = args["listener"]
        self.port = args["port"]
        self.authority = args["authority"]
        self.resolver = args["dns_resolver"]
        self.zones_dir = args["zones_dir"]

    def get_args(command):
        """
        Sets up argparse and collects arguments.
        """
        super_args = ServerPlugin.get_args(command)

        parser = argparse.ArgumentParser(description='DNS Server')

        # Network Configuration
        parser.add_argument('--interface', action='store', help='Interface to listen on', default=INTERFACE)
        parser.add_argument('--listener', action='store', choices=(DNSServer.socket_TCP, DNSServer.socket_UDP,
                                                                   DNSServer.netfilter_queue),
                            help='Set the listener (Netfilterqueue is linux only)', default=DNSServer.socket_UDP)
        parser.add_argument('--port', type=int, action='store', help='DNS Server port to listen on', default=PORT)

        # Zones
        parser.add_argument("--zones-dir", action='store', help="Zones directory", default=ZONES_DIR)

        # Authority
        parser.add_argument('--authority', action='store_true', help='States that the DNS server is the authority server of'
                                                                     ' all DNS responses')
        # DNS Resolver
        parser.add_argument('--dns-resolver', action='store', help="Specify a DNS resolver to forward DNS queries",
                            default=DNS_RESOLVER)
        parser.add_argument('--no-forwarding', action='store_true', help='Disable forwarding DNS queries to a DNS resolver',
                            default=False)

        parser.add_argument('--log', action='store', choices=("debug", "info", "error"), help="Sets the log level",
                            default=LOG_LEVEL)
        args, _ = parser.parse_known_args(command)
        args = vars(args)
        super_args.update(args)
        return super_args

    def run(self, args, logger):
        """
        Starts the DNS Service
        """
        self.running = True
        self.logger = logger
        # Setup the Listener
        if self.listener == DNSServer.netfilter_queue:  # Netfilter Queue
            self.nfqueue_num = random.randint(11, 255)
            os.system(
                'iptables -t mangle -A PREROUTING -p udp --dport ' + str(self.port) + ' -j NFQUEUE --queue-num %d' % self.nfqueue_num)
            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(self.nfqueue_num, self.process_packet_netfilter)

        elif self.listener == DNSServer.socket_UDP:  # UDP Socket
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                self.sock.bind(('0.0.0.0', self.port))
            except socket.error as err:
                raise Exception("Error opening UDP socket")
        elif self.listener == DNSServer.socket_TCP:  # TCP Socket
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind(('0.0.0.0', self.port))
            except Exception as err:
                raise Exception("Error opening TCP socket")
        else:  # None selected
            raise Exception("No listener has been selected")

        # Load the DNS zones this server will support
        self.load_zones()
        self.logger.debug("Starting the DNS service")
        self.write_startup_file(args, logger)

        # Netfilter
        if self.listener == DNSServer.netfilter_queue:
            try:
                self.nfqueue.run()
            except KeyboardInterrupt:
                os.system('iptables -t mangle -D PREROUTING '
                          '-p udp --dport ' + str(self.port) + ' -j NFQUEUE --queue-num %d' % self.nfqueue_num)

        # Socket UDP
        elif self.listener == DNSServer.socket_UDP:
            while True:
                try:
                    data = self.sock.recv(1024)
                except socket.timeout:
                    continue
                response_packet = self.build_response_packet(data)

                if response_packet is not None:
                    send(response_packet, verbose=0)#, iface=self.interface)

        # Socket TCP
        elif self.listener == DNSServer.socket_TCP:
            self.sock.listen(10000)
            self.logger.debug("Socket is listening")

            # Continuously accept new connections
            while True:
                try:
                    connection, addr = self.sock.accept()

                    # Two byte length field
                    message_length = connection.recv(2)
                    if not message_length:
                        continue

                    message_length = int(message_length[0]) * 256 + int(message_length[1])

                    # Receive the DNS contents
                    dns_contents = connection.recv(message_length)
                    if not dns_contents:
                        continue

                    # Build response
                    response_packet = self.build_response_packet(dns_contents, False)

                    if response_packet is not None:
                        length = len(response_packet)
                        connection.send(length.to_bytes(2, byteorder='big') + raw(response_packet))

                    connection.close()
                except KeyboardInterrupt:
                    self.sock.close()
                    break
                except Exception:
                    pass

    def load_zones(self):
        """
        Loads the DNS Zones in the zones directory specified (zones_dir)
        """
        zones_dir = os.path.join(BASEPATH, self.zones_dir)
        self.logger.debug("Loading the DNS zones from %s", zones_dir)

        # Each file in the zones directory is a domain
        for domain in os.listdir(zones_dir):
            try:
                self.zones[domain] = dns.zone.from_file(zones_dir + domain, domain, rdclass=1, relativize=False)
                self.logger.debug("Loaded zone: " + domain)
            except DNSException:
                self.logger.error("Error reading zone file:" + domain)

    def forward_dns_query(self, packet: IP):
        """
        Forwards the DNS query to a real DNS resolver and returns the DNS response
        """

        dns_response = sr1(
            IP(dst=self.resolver) /
            UDP(sport=5000, dport=53) /
            DNS(rd=1, id=packet[DNS].id, qd=packet[DNSQR]),
            verbose=0
        )

        return dns_response[DNS]

    def get_dns_query_info(self, packet: IP):
        """
        Extract information from the DNS query
        """
        question_name = packet[DNSQR].qname.decode("utf-8")
        question_type = dns.rdatatype.to_text(packet[DNSQR].qtype)

        error = False

        # Get the first level domain name (e.g. www.google.com -> google.com)
        domain_name = question_name[:-1]  # Remove ending "."
        try:
            domain_name = get_fld(domain_name, fix_protocol=True)
        except Exception as e:
            self.logger.error("ERROR: Question Name: " + question_name + " - " + str(e))
            error = True

        return question_name, domain_name, question_type, error

    def get_resource_records(self, domain_name, question_name, question_type):
        """
        Gets the appropriate resource record loaded earlier from the zone file
        """
        resource_records = None

        data = self.zones[domain_name].get_rdataset(question_name, question_type)

        if data is None:
            # NXDOMAIN
            return resource_records, 0

        # Build the resource records using scapy (DNSRR)
        for record in data:
            resource_record = DNSRR(rrname=question_name, type=question_type, ttl=data.ttl)
            resource_record_log = "Adding record: " + question_name + ' ' + str(data.ttl) + ' ' + question_type + ' '

            if question_type == 'MX':
                resource_record_log += record.to_text()
                # DNS RDATA FORMAT: Preference (16 bit integer) + Exchange (DNS Name)
                resource_record[DNSRR].rdata = \
                    struct.pack("!H", record.preference) + record.exchange.to_wire(None, None)
            elif question_type == 'TXT':
                # Retrieve only the first string in the TXT record to avoid duplicate quotes
                resource_record_log += dns.rdata._escapify(record.strings[0])
                resource_record[DNSRR].rdata = dns.rdata._escapify(record.strings[0])
            else:
                # Default: Records tested that work: A, NS, CNAME
                resource_record_log += record.to_text()
                resource_record[DNSRR].rdata = record.to_text()

            #self.logger.debug(resource_record_log)

            if resource_records is None:
                resource_records = resource_record
            else:
                resource_records = resource_records / resource_record

        return resource_records, len(data)

    def build_dns_response(self, packet):
        """
        Build the DNS response packet using one of the following methods:
        1) Load the resource record(s) from a manually configured DNS zone file (if exists)
        OTHERWISE, if enabled:
        2) Send a DNS query to a DNS resolver and copy the DNS resource records
        """

        # Build response packet with empty DNS information and domain name error
        dns_response = DNS(id=packet[DNS].id, rcode=3, ra=1, qr=1, qdcount=1, ancount=0, qd=packet[DNS].qd)

        # Extract information from the DNS query
        question_name, domain_name, question_type, dns_query_error = self.get_dns_query_info(packet)

        info_log = "Query - Name: " + question_name + " | FLD: " + domain_name + \
                   " | Record Type: " + question_type

        if domain_name in self.zones and dns_query_error is False:
            # If we have a zone for this domain
            self.logger.debug("Found manually configured domain: " + domain_name)

            # Get the resource records
            (resource_records, count) = self.get_resource_records(domain_name, question_name, question_type)

            if count > 0:
                dns_response = DNS(id=packet[DNS].id, rcode=0, ra=1, qr=1, qdcount=1, ancount=count, qd=packet[DNS].qd,
                                   an=resource_records)

            self.logger.debug(info_log + " | Action: Zone")

        elif self.resolver is not None:
            # Forward the packet to a real DNS resolver
            self.logger.debug("No manually configured zone file for this domain; forwarding packet to " + self.resolver)
            dns_response = self.forward_dns_query(packet)
            self.logger.debug("Response from DNS resolver: " + pformat(dns_response))

            self.logger.debug(info_log + " | Action: Forwarding")

        if self.authority is True:
            dns_response[DNS].aa = 1

        return dns_response

    def process_packet_netfilter(self, listener_packet):
        """
        Callback function for each packet received by netfilter
        """
        if not self.running:
            return
        response_packet = self.build_response_packet(listener_packet)
        send(response_packet, verbose=0, iface=self.interface)

    def stop(self):
        """
        Stops this server.
        """
        self.running = False

        if self.listener == DNSServer.netfilter_queue:
            # Give the handlers two seconds to leave the callbacks before we forcibly unbind
            # the queues.
            time.sleep(2)
            self.nfqueue.unbind()
            os.system('iptables -t mangle -D PREROUTING '
                      '-p udp --dport ' + str(self.port) + ' -j NFQUEUE --queue-num %d' % self.nfqueue_num)
        # Socket UDP
        elif self.listener == DNSServer.socket_UDP:
            if self.sock:
                self.sock.close()
        # Socket TCP
        elif self.listener == DNSServer.socket_TCP:
            if self.sock:
                self.sock.close()

        ServerPlugin.stop(self)

    def build_response_packet(self, listener_packet, raw_socket=True):
        """
        Build the DNS response packet
        - If raw_socket is enabled include the Network and Transport Layer
        """

        packet = None

        # Netfilter
        if self.listener == DNSServer.netfilter_queue:
            packet = IP(listener_packet.get_payload())
            listener_packet.drop()

        # No transformations - UDP
        elif self.listener == DNSServer.socket_UDP:
            # Raw packet to scapy packet
            packet = IP(listener_packet)

        # No transformations - TCP
        elif self.listener == DNSServer.socket_TCP:
            packet = DNS(listener_packet)

        if packet is None or not packet.haslayer(DNS):  # if this packet does not have DNS layer
            return None

        #self.logger.debug("Received the following packet " + str(self.packet_counter + 1) + ": " + pformat(packet))

        # Ignore DNS responses
        if packet[DNS].qr == 1:
            #self.logger.debug("Discarding DNS response packet\n")
            return None

        self.packet_counter += 1

        # Build DNS response packet
        dns_response = self.build_dns_response(packet)

        #self.logger.debug(dns_response)

        if raw_socket is True:
            response_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                     UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                     dns_response

            response_packet = IP(raw(response_packet))

        else:
            response_packet = dns_response

        #self.logger.debug("Response packet " + str(self.packet_counter) + ": " +
        #                  pformat(response_packet) + "\n")

        return response_packet


def main(args):
    """
    Run the DNS server
    """
    server = DNSServer(args)

    if "dry_run" not in args:
        server.start()

    return server

if __name__ == "__main__":
    main(DNSServer.get_args(sys.argv[1:]))
