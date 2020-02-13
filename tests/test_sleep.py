from scapy.all import IP, TCP
import evolve
import actions.utils
import actions.strategy
import actions.packet
import actions.sleep
import sys
# Include the root of the project
sys.path.append("..")


def test_basic_sleep(log_level):
    """
    Tests the sleep action primitive
    """
    logger = evolve.logger
    evolve.set_logger(log_level)

    sleep = actions.sleep.SleepAction(.5)
    assert str(sleep) == "sleep{0.5}", "Sleep returned incorrect string representation: %s" % str(sleep)

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP()/("data"))
    packet1, packet2 = sleep.run(packet, logger)

    assert packet1.sleep == .5, "Packet had wrong sleep value"

def test_sleep_str_parse(log_level):
    """
    Tests stringing and parsing a sleep action with a float sleep time
    """
    logger = evolve.logger
    evolve.set_logger(log_level)

    strat = actions.utils.parse("[TCP:flags:A]-sleep{0.5}-|", logger)

    assert strat.out_actions[0].action_root.time == .5
    assert "0.5" in str(strat)
