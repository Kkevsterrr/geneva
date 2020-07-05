from scapy.all import IP, TCP
import evolve
import actions.utils
import actions.strategy
import layers.packet
import actions.sleep
import sys
# Include the root of the project
sys.path.append("..")


def test_basic_sleep(logger):
    """
    Tests the sleep action primitive
    """
    sleep = actions.sleep.SleepAction(.5)
    assert str(sleep) == "sleep{0.5}", "Sleep returned incorrect string representation: %s" % str(sleep)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP()/("data"))
    packet1, packet2 = sleep.run(packet, logger)

    assert packet1.sleep == .5, "Packet had wrong sleep value"

def test_sleep_str_parse(logger):
    """
    Tests stringing and parsing a sleep action with a float sleep time
    """
    strat = actions.utils.parse("[TCP:flags:A]-sleep{0.5}-|", logger)

    assert strat.out_actions[0].action_root.time == .5
    assert "0.5" in str(strat)
