import os
import sys
import pytest

from scapy.all import *

# Add the path to the engine so we can import it
BASEPATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASEPATH)

import layers.packet
import engine

def test_engine():
    """
    Basic engine test
    """
    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as _:
        os.system("curl http://example.com?q=ultrasurf")


def test_default_args():
    """
    Tests engine can be created without specifying all of the args
    """
    with engine.Engine(80, "") as eng:
        assert eng.output_directory == "trials"
        assert eng.environment_id is not None


# Test does not generate a RA, it times out - need a different way
@pytest.mark.skip()
def test_detect_rstacks():
    """
    Tests the engine detects & records seeing RA packets
    """
    with engine.Engine(80, "") as eng:
        os.system("curl 8.8.8.8:80")
        assert eng.censorship_detected


def test_nat_unit():
    """
    Test NAT functionality
    """
    forwarder = {
        "sender_ip" : "1.1.1.1",
        "routing_ip": "2.2.2.2",
        "forward_ip": "3.3.3.3"
    }
    pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP()/Raw("test")
    packet = layers.packet.Packet(pkt)
    eng = engine.Engine(80, "", forwarder=forwarder)
    eng.do_nat(packet)
    packet[IP].src == "2.2.2.2"
    packet[IP].dst == "3.3.3.3"
    eng.mysend(packet)

def test_engine_sleep():
    """
    Basic engine test with sleep action
    """
    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "[TCP:flags:S]-sleep{1}-|"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="info") as eng:
        os.system("curl http://example.com?q=ultrasurf")


@pytest.mark.skip()
def test_engine_sleep_inbound():
    """
    Basic engine test with sleep action inbound.
    """
    port = 80
    # Strategy to use in opposite direction
    strategy = "\/ [TCP:flags:SA]-sleep{1}-|"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as eng:
        os.system("curl http://example.com?q=ultrasurf")


def test_engine_trace():
    """
    Basic engine test with trace
    """
    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "[TCP:flags:PA]-trace{2:10}-|"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as eng:
        os.system("curl -m 5 http://example.com?q=ultrasurf")


def test_engine_drop():
    """
    Basic engine test with drop
    """
    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "\/ [TCP:flags:SA]-drop-|"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as eng:
        os.system("curl -m 3 http://example.com?q=ultrasurf")

