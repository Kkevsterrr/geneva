import sys
import pytest
# Include the root of the project
sys.path.append("..")

import actions.trace
import layers.packet
import actions.strategy
import actions.utils
import evolve

from scapy.all import IP, TCP


def test_trace(logger):
    """
    Tests the trace action primitive.
    """
    trace = actions.trace.TraceAction(start_ttl=1, end_ttl=3)

    assert str(trace) == "trace{1:3}", "Trace returned incorrect string representation: %s" % str(trace)
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    trace.run(packet, logger)

    print("Testing that trace will not run twice:")
    assert trace.run(packet, logger) == (None, None)

    trace = actions.trace.TraceAction(start_ttl=1, end_ttl=3)
    packet = layers.packet.Packet(TCP())
    assert trace.run(packet, logger) == (packet, None)

    s = "[TCP:flags:PA]-trace{1:3}-| \/ "
    assert str(actions.utils.parse(s, logger)) == s

    assert not trace.parse("10:4", logger)
    assert not trace.parse("10:hi", logger)
    assert not trace.parse("", logger)
