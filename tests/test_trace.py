import logging
import sys

# Include the root of the project
sys.path.append("..")


import actions.strategy
import actions.packet
import actions.utils
import actions.trace
import actions.layer

from scapy.all import IP, TCP, UDP, DNS, DNSQR, sr1


logger = logging.getLogger("test")


def test_trace_error_cases():
    """
    Tests that trace handles edge cases.
    """
    # No IP header means the packet should just be returned
    packet = actions.packet.Packet(TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    trace = actions.trace.TraceAction(None)
    p1, p2 = trace.run(packet, logger)
    assert p2 is None
    assert p1 == packet

    # Mark the trace as having run already - it should not run again
    trace.ran = True
    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    p1, p2 = trace.run(packet, logger)
    assert p1 is None
    assert p2 is None
