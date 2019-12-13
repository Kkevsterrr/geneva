import logging
import pytest

import actions.tree
import actions.drop
import actions.tamper
import actions.duplicate
import actions.sleep
import actions.utils
import actions.strategy

from scapy.all import IP, TCP

logger = logging.getLogger("test")


def test_run():
    """
    Tests strategy execution.
    """
    strat1 = actions.utils.parse("[TCP:flags:R]-duplicate-| \/", logger)
    strat2 = actions.utils.parse("[TCP:flags:S]-drop-| \/", logger)
    strat3 = actions.utils.parse("[TCP:flags:A]-duplicate(tamper{TCP:dataofs:replace:0},)-| \/", logger)
    strat4 = actions.utils.parse("[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14539}(tamper{TCP:seq:corrupt},),),))-| \/", logger)

    p1 = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    packets = strat1.act_on_packet(p1, logger, direction="out")
    assert packets, "Strategy dropped SYN packets"
    assert len(packets) == 1
    assert packets[0]["TCP"].flags == "S"

    p1 = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    packets = strat2.act_on_packet(p1, logger, direction="out")
    assert not packets, "Strategy failed to drop SYN packets"

    p1 = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="A", dataofs=5))
    packets = strat3.act_on_packet(p1, logger, direction="out")
    assert packets, "Strategy dropped packets"
    assert len(packets) == 2, "Incorrect number of packets emerged from forest"
    assert packets[0]["TCP"].dataofs == 0, "Packet tamper failed"
    assert packets[1]["TCP"].dataofs == 5, "Duplicate packet was tampered"

    p1 = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="A", dataofs=5, chksum=100))
    packets = strat4.act_on_packet(p1, logger, direction="out")
    assert packets, "Strategy dropped packets"
    assert len(packets) == 3, "Incorrect number of packets emerged from forest"
    assert packets[0]["TCP"].flags == "R", "Packet tamper failed"
    assert packets[0]["TCP"].chksum != p1["TCP"].chksum, "Packet tamper failed"
    assert packets[1]["TCP"].flags == "S", "Packet tamper failed"
    assert packets[1]["TCP"].chksum != p1["TCP"].chksum, "Packet tamper failed"
    assert packets[1]["TCP"].seq != p1["TCP"].seq, "Packet tamper failed"
    assert packets[2]["TCP"].flags == "A", "Duplicate failed"

    strat4 = actions.utils.parse("[TCP:load:]-tamper{TCP:load:replace:mhe76jm0bd}(fragment{ip:-1:True}(tamper{IP:load:corrupt},drop),)-| \/ ", logger)
    p1 = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    packets = strat4.act_on_packet(p1, logger)

    # Will fail with scapy 2.4.2 if packet is reparsed
    strat5 = actions.utils.parse("[TCP:options-eol:]-tamper{TCP:load:replace:o}(tamper{TCP:dataofs:replace:11},)-| \/", logger)
    p1 = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    packets = strat5.act_on_packet(p1, logger)


def test_pretty_print():
    """
    Tests if the string representation of this strategy is correct
    """
    logger = logging.getLogger("test")
    strat = actions.utils.parse("[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/ ", logger)
    correct = "TCP:flags:A\nduplicate\n├── tamper{TCP:flags:replace:R}\n│   └── tamper{TCP:chksum:corrupt}\n│       └──  ===> \n└──  ===> \n \n \/ \n "
    assert strat.pretty_print() == correct


def test_sleep_parse_handling():
    """
    Tests that the sleep action handles bad parsing.
    """

    print("Testing incorrect parsing:")
    assert not actions.sleep.SleepAction().parse("THISHSOULDFAIL", logger)

    assert actions.sleep.SleepAction().parse("10.5", logger)
