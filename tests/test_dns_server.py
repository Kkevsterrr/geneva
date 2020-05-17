# Scapy modules
from scapy.layers.dns import IP, UDP, raw, DNS as DNS_, DNSQR, struct

# DNS Modules
import dns.zone

# Import the root of the project: used to import DNSServer
import os
import sys
import inspect
import logging

import pytest

basepath = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(basepath)
sys.path.insert(0, parent_dir)

import evolve
from plugins.dns.server import DNSServer

# Default values
INTERFACE = 'lo'
LISTENER = DNSServer.socket_UDP
PORT = 53
AUTHORITY = False
DNS_RESOLVER = "1.1.1.1"
LOG_DIR = basepath + "/DNS/"
ZONES_DIR = basepath + "/DNS/zones/"
LOGGING_LEVEL = logging.INFO

# Error definitions
RECORD_COUNT_ERROR = "record_count_error"
RECORD_VALUE_ERROR = "record_value_error"


@pytest.mark.skip()
@pytest.mark.parametrize("listener", [DNSServer.socket_UDP, DNSServer.socket_TCP, DNSServer.netfilter_queue])
def test_dns_server(listener, logger):
    """
    Tests the main method
    """
    # TODO test is currently disabled, will be replaced by a test that
    # tests the full functionality of receiving DNS queries
    args = {
        'interface': INTERFACE,
        'port': PORT,
        'authority': AUTHORITY,
        'zones_dir': ZONES_DIR,
        'log_dir': LOG_DIR,
        'dry_run': True,
        'listener': listener
    }

    server = DNSServer.server.main(args)


@pytest.mark.parametrize("listener", [DNSServer.socket_UDP, DNSServer.socket_TCP, DNSServer.netfilter_queue])
def test_zone_records(listener, logger):
    """
    Tests if it can read the information in the zones file correctly
    """
    args = {
        "interface": INTERFACE,
        "listener": listener,
        "port": PORT,
        "authority": AUTHORITY,
        "dns_resolver": DNS_RESOLVER,
        "zones_dir": ZONES_DIR
    }

    # Testing variable
    server = DNSServer(args, logger=logger)

    server.load_zones()

    # Answer variables
    example_com = dns.zone.from_file(ZONES_DIR + "example.com", "example.com", rdclass=1, relativize=False)
    example2_com = dns.zone.from_file(ZONES_DIR + "example2.com", "example2.com", rdclass=1, relativize=False)

    # ---------------- Testing A records -----------------
    # No errors
    check_records(server, example_com, "example.com.", "A")
    check_records(server, example_com, "ns1.example.com.", "A")
    check_records(server, example_com, "ns2.example.com.", "A")
    check_records(server, example_com, "mail.example.com.", "A")
    check_records(server, example_com, "mail2.example.com.", "A")
    check_records(server, example_com, "www2.example.com.", "A")

    # Errors
    # ns1.example.com. has 2 A records while ns2.example.com. has 1 A record
    check_records(server, example_com, "ns2.example.com.", "A", False, RECORD_COUNT_ERROR, "ns1.example.com.")
    # Both example.com. and ns1.example.com. have 2 A records but the value of those records are different
    check_records(server, example_com, "example.com.", "A", False, RECORD_VALUE_ERROR, "ns1.example.com.")

    # No errors with a different zone file
    check_records(server, example2_com, "example2.com.", "A")
    check_records(server, example2_com, "ns1.example2.com.", "A")
    check_records(server, example2_com, "ns2.example2.com.", "A")
    check_records(server, example2_com, "mail.example2.com.", "A")
    check_records(server, example2_com, "mail2.example2.com.", "A")
    check_records(server, example2_com, "www2.example2.com.", "A")

    # Errors with a different zone
    # ns1.example.com. has 2 A records while ns2.example.com. has 1 A record
    check_records(server, example2_com, "ns2.example2.com.", "A", False, RECORD_COUNT_ERROR, "ns1.example2.com.")
    # Both example.com. and ns1.example.com. have 2 A records but the value of those records are different
    check_records(server, example2_com, "example2.com.", "A", False, RECORD_VALUE_ERROR, "ns1.example2.com.")

    # ---------------- Testing TXT records -----------------
    # No errors
    check_records(server, example_com, "example.com.", "TXT")
    check_records(server, example2_com, "example2.com.", "TXT")

    # ---------------- Testing MX records -----------------
    # No errors
    check_records(server, example_com, "example.com.", "MX")
    check_records(server, example2_com, "example2.com.", "MX")

    # ---------------- Testing NS records -----------------
    # No errors
    check_records(server, example_com, "example.com.", "NS")
    check_records(server, example2_com, "example2.com.", "NS")

    # ---------------- Testing CNAME records -----------------
    # No errors
    check_records(server, example_com, "www.example.com.", "CNAME")
    check_records(server, example2_com, "www.example2.com.", "CNAME")

    # ---------------- Testing NXDOMAIN -----------------
    # No errors
    check_nxdomain(server, "www3.example.com.", "A")
    check_nxdomain(server, "www3.example.com.", "TXT")
    check_nxdomain(server, "www3.example.com.", "NS")
    check_nxdomain(server, "www3.example.com.", "MX")
    check_nxdomain(server, "www3.example.com.", "CNAME")

def test_forwarding(logger):
    """
    Tests if DNSServer properly enables and disables forwarding of DNS queries that it does not have answers to
    """
    args = {
        "interface": INTERFACE,
        "listener": LISTENER,
        "port": PORT,
        "authority": AUTHORITY,
        "dns_resolver": DNS_RESOLVER,
        "zones_dir": ZONES_DIR
    }

    args_no_forward = {
        "interface": INTERFACE,
        "listener": LISTENER,
        "port": PORT,
        "authority": AUTHORITY,
        "dns_resolver": None,
        "zones_dir": ZONES_DIR
    }

    # Testing variable
    server = DNSServer(args, logger=logger)
    server_no_forward = DNSServer(args_no_forward, logger=logger)

    # Zone loading happens during actual startup, so load it here
    server.load_zones()
    server_no_forward.load_zones()

    # Answer variables
    example_com = dns.zone.from_file(ZONES_DIR + "example.com", "example.com", rdclass=1, relativize=False)
    example2_com = dns.zone.from_file(ZONES_DIR + "example2.com", "example2.com", rdclass=1, relativize=False)

    # Test if it can forward a query
    check_record_exists(server, "google.com.", "A")
    check_record_exists(server, "msn.com.", "A")

    # ------------- NXDOMAIN ---------------
    # NXDOMAIN for all domains outside of the zones configured
    check_nxdomain(server_no_forward, "google.com.", "A")
    check_nxdomain(server_no_forward, "google.com.", "TXT")
    check_nxdomain(server_no_forward, "google.com.", "NS")
    check_nxdomain(server_no_forward, "google.com.", "MX")
    check_nxdomain(server_no_forward, "google.com.", "CNAME")

    check_nxdomain(server_no_forward, "msn.com.", "A")
    check_nxdomain(server_no_forward, "msn.com.", "TXT")
    check_nxdomain(server_no_forward, "msn.com.", "NS")
    check_nxdomain(server_no_forward, "msn.com.", "MX")
    check_nxdomain(server_no_forward, "msn.com.", "CNAME")

    # NXDOMAIN for domains declared in the zones but does not exist
    check_nxdomain(server_no_forward, "www3.example.com.", "A")
    check_nxdomain(server_no_forward, "www3.example.com.", "TXT")
    check_nxdomain(server_no_forward, "www3.example.com.", "NS")
    check_nxdomain(server_no_forward, "www3.example.com.", "MX")
    check_nxdomain(server_no_forward, "www3.example.com.", "CNAME")

    # ------------- Resource Records ---------------
    # Resource Records declared in the zones

    check_records(server_no_forward, example_com, "example.com.", "A")
    check_records(server_no_forward, example_com, "example.com.", "TXT")
    check_records(server_no_forward, example_com, "example.com.", "MX")
    check_records(server_no_forward, example_com, "example.com.", "NS")
    check_records(server_no_forward, example_com, "www.example.com.", "CNAME")

    check_records(server_no_forward, example2_com, "example2.com.", "A")
    check_records(server_no_forward, example2_com, "example2.com.", "TXT")
    check_records(server_no_forward, example2_com, "example2.com.", "MX")
    check_records(server_no_forward, example2_com, "example2.com.", "NS")
    check_records(server_no_forward, example2_com, "www.example2.com.", "CNAME")


def test_authority_reply(logger):
    """
    Tests that the DNS responses correctly include the authority flag when set
    """
    args = {
        "interface": INTERFACE,
        "listener": LISTENER,
        "port": PORT,
        "authority": True,
        "dns_resolver": DNS_RESOLVER,
        "zones_dir": ZONES_DIR
    }

    args_no_auth = {
        "interface": INTERFACE,
        "listener": LISTENER,
        "port": PORT,
        "authority": False,
        "dns_resolver": DNS_RESOLVER,
        "zones_dir": ZONES_DIR
    }

    server = DNSServer(args, logger=logger)
    server_no_auth = DNSServer(args_no_auth, logger=logger)

    # Zone loading happens during actual startup, so load it here
    server.load_zones()
    server_no_auth.load_zones()

    example_com = dns.zone.from_file(ZONES_DIR + "example.com", "example.com", rdclass=1, relativize=False)

    # Test with authority - Zones configuration
    check_records(server, example_com, "example.com.", "A", authority=True)
    check_records(server, example_com, "example.com.", "TXT", authority=True)
    check_records(server, example_com, "example.com.", "MX", authority=True)
    check_records(server, example_com, "example.com.", "NS", authority=True)
    check_records(server, example_com, "www.example.com.", "CNAME", authority=True)

    # Test with no authority - Zone configuration
    check_records(server_no_auth, example_com, "example.com.", "A", authority=False)
    check_records(server_no_auth, example_com, "example.com.", "TXT", authority=False)
    check_records(server_no_auth, example_com, "example.com.", "MX", authority=False)
    check_records(server_no_auth, example_com, "example.com.", "NS", authority=False)
    check_records(server_no_auth, example_com, "www.example.com.", "CNAME", authority=False)

    # Test with authority - Zone configuration - NXDOMAIN
    check_nxdomain(server, "www3.example.com.", "A", authority=True)
    check_nxdomain(server, "www3.example.com.", "TXT", authority=True)
    check_nxdomain(server, "www3.example.com.", "NS", authority=True)
    check_nxdomain(server, "www3.example.com.", "MX", authority=True)
    check_nxdomain(server, "www3.example.com.", "CNAME", authority=True)

    # Test without authority - Zone configuration - NXDOMAIN
    check_nxdomain(server_no_auth, "www3.example.com.", "A", authority=False)
    check_nxdomain(server_no_auth, "www3.example.com.", "TXT", authority=False)
    check_nxdomain(server_no_auth, "www3.example.com.", "NS", authority=False)
    check_nxdomain(server_no_auth, "www3.example.com.", "MX", authority=False)
    check_nxdomain(server_no_auth, "www3.example.com.", "CNAME", authority=False)

    # Test with authority - DNS Forwarding - Exists
    check_record_exists(server, "google.com.", "A", authority=True)
    check_record_exists(server, "msn.com.", "A", authority=True)

    # Test without authority - DNS Forwarding - Exists
    check_record_exists(server_no_auth, "google.com.", "A", authority=False)
    check_record_exists(server_no_auth, "msn.com.", "A", authority=False)

    # Test with authority - DNS Forwarding - NXDOMAIN
    check_nxdomain(server, "12398.google.com.", "A", authority=True)
    check_record_exists(server, "12398.msn.com.", "A", authority=True)

    # Test without authority - DNS Forwarding - NXDOMAIN
    check_nxdomain(server_no_auth, "12398.google.com.", "A", authority=False)
    check_record_exists(server_no_auth, "12398.msn.com.", "A", authority=False)


def test_tld_does_not_exist(logger):
    """
    Tests that if one queries for a TLD that does not exist, the program will simply respond with NXDOMAIN
    :return:
    """
    args = {
        "interface": INTERFACE,
        "listener": LISTENER,
        "port": PORT,
        "authority": AUTHORITY,
        "dns_resolver": DNS_RESOLVER,
        "zones_dir": ZONES_DIR
    }

    args_no_auth = {
        "interface": INTERFACE,
        "listener": LISTENER,
        "port": PORT,
        "authority": AUTHORITY,
        "dns_resolver": None,
        "zones_dir": ZONES_DIR
    }

    server = DNSServer(args, logger=logger)
    server_no_forward = DNSServer(args_no_auth, logger=logger)

    # Zone loading happens during actual startup, so load it here
    server.load_zones()
    server_no_forward.load_zones()

    check_nxdomain(server_no_forward, "google.tp.", "A")
    check_nxdomain(server_no_forward, "google.techn.", "CNAME")
    check_nxdomain(server_no_forward, "google.techno.", "MX")
    check_nxdomain(server_no_forward, "google.technol.", "TXT")
    check_nxdomain(server_no_forward, "google.technolo.", "NS")

    check_nxdomain(server, "google.tp.", "A")
    check_nxdomain(server, "google.techn.", "CNAME")
    check_nxdomain(server, "google.techno.", "MX")
    check_nxdomain(server, "google.technol.", "TXT")
    check_nxdomain(server, "google.technolo.", "NS")


def check_nxdomain(server, query, query_type, authority=False):
    """
    Tests that the DNS response marks the query as NXDOMAIN
    """

    dns_query = IP(dst="127.0.0.1") / UDP(dport=53) / \
                DNS_(rd=1, qd=DNSQR(qname=query, qtype=query_type))
    dns_query = IP(raw(dns_query))

    response = server.build_dns_response(dns_query)

    assert response[DNS_].rcode == 3
    assert response[DNS_].ancount == 0

    if authority is True:
        assert response[DNS_].aa == 1


def get_value(record, query_type):
    """
    Gets the value (rdata) of a specific resource record
    """

    if query_type == "TXT":
        return dns.rdata._escapify(record.strings[0])
    elif query_type == "MX":
        return (struct.pack("!H", record.preference) + record.exchange.to_wire(None, None)).decode('utf-8')

    return record.to_text()


def check_record_exists(server, query, query_type, authority=False):
    """
    Checks if there is at least one resource record.
    Optionally, check if the DNS response has the "Authoritative Answer" flag set
    """
    dns_query = IP(dst="127.0.0.1") / UDP(dport=53) / \
                DNS_(rd=1, qd=DNSQR(qname=query, qtype=query_type))
    dns_query = IP(raw(dns_query))

    response = server.build_dns_response(dns_query)

    assert response[DNS_].rcode == 0
    assert response[DNS_].ancount > 0

    assert response[DNS_].an[0].rdata != ''

    if authority is True:
        assert response[DNS_].aa == 1


def check_records(server, answer, query, query_type, authority=False, error=None, other_query=None):
    """
    Checks that the A record value & record count matches (if error is None)
    Otherwise, if error is specified, then it checks to make sure that the error is achieved
    Optionally, check if the DNS response has the "Authoritative Answer" flag set
    """

    dns_query = IP(dst="127.0.0.1") / UDP(dport=53) / \
                DNS_(rd=1, qd=DNSQR(qname=query, qtype=query_type))
    dns_query = IP(raw(dns_query))

    response = server.build_dns_response(dns_query)
    if other_query is None:
        data = answer.find_rdataset(query, query_type)
    else:
        data = answer.find_rdataset(other_query, query_type)

    if error is None:
        assert len(data) == response[DNS_].ancount
        for i in range(response[DNS_].ancount):
            # DEBUGGING REQUIRED FOR SCAPY UPGRADES to field types
            # print("Comparison check")
            # print(type(response[DNS_].an[i].type))
            # print(response[DNS_].an[i].type)
            # print(response[DNS_].an[i].show())
            # print(type(response[DNS_].an[i].rdata))
            # print(response[DNS_].an[i].rdata)

            if response[DNS_].an[i].type == 16:  # TXT
                assert get_value(data[i], query_type) == response[DNS_].an[i].rdata[0]
                continue
            elif response[DNS_].an[i].type == 1:  # A
                assert get_value(data[i], query_type) == response[DNS_].an[i].rdata
                continue
            assert get_value(data[i], query_type) == response[DNS_].an[i].rdata.decode('utf-8')
    elif error == RECORD_COUNT_ERROR:
        assert len(data) != response[DNS_].ancount
    elif error == RECORD_VALUE_ERROR:
        assert len(data) == response[DNS_].ancount
        for i in range(response[DNS_].ancount):
            # DEBUGGING REQUIRED FOR SCAPY UPGRADES to field types
            # print("Comparison check")
            # print(type(response[DNS_].an[i].type))
            # print(response[DNS_].an[i].type)
            # print(response[DNS_].an[i].show())
            # print(type(response[DNS_].an[i].rdata))
            # print(response[DNS_].an[i].rdata)

            if response[DNS_].an[i].type == 16:  # TXT
                assert get_value(data[i], query_type) != response[DNS_].an[i].rdata[0]
                continue
            elif response[DNS_].an[i].type == 1:  # A
                assert get_value(data[i], query_type) != response[DNS_].an[i].rdata
                continue
            assert get_value(data[i], query_type) != response[DNS_].an[i].rdata.decode('utf-8')

    if authority is True:
        assert response[DNS_].aa == 1



