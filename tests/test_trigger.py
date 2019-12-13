import logging
import sys
# Include the root of the project
sys.path.append("..")

import actions.packet
import actions.strategy
import actions.tamper
import actions.utils

from scapy.all import IP, TCP

logger = logging.getLogger("test")


def test_trigger_gas():
    """
    Tests triggers having gas, including changing that gas while in use
    """

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))
    trigger = actions.trigger.Trigger("field", "flags", "TCP", trigger_value="SA", gas=1)
    print(trigger)
    assert trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)
    print(trigger)
    # test add gas #
    trigger.add_gas(3)
    assert trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)

    # Test disable, set, and enable gas #
    trigger.disable_gas()
    assert trigger.is_applicable(packet, logger)
    trigger.set_gas(3)
    assert trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)
    trigger.enable_gas()
    trigger.set_gas(2)
    assert trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)


def test_bomb_trigger_gas():
    """
    Tests triggers having bomb gas, including changing that gas while in use
    """

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))
    trigger = actions.trigger.Trigger("field", "flags", "TCP", trigger_value="SA", gas=-1)
    print(trigger)
    assert not trigger.is_applicable(packet, logger), "trigger should not fire on first run"
    assert trigger.is_applicable(packet, logger), "trigger should fire on second run"
    print(trigger)
    # test add gas #
    trigger.add_gas(-3)
    assert not trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)

    # Test disable, set, and enable gas #
    trigger.disable_gas()
    assert trigger.is_applicable(packet, logger)
    trigger.set_gas(-3)
    assert not trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)
    trigger.enable_gas()
    trigger.set_gas(-2)
    assert not trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)


def test_trigger_parse_gas():
    """
    Tests triggers having gas, including changing that gas while in use
    """

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))


    # parse a trigger with 1 gas
    trigger = actions.trigger.Trigger.parse("TCP:flags:SA:1")
    assert trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)

    # parse a trigger with no gas left
    trigger = actions.trigger.Trigger.parse("TCP:flags:SA:0")
    assert not trigger.is_applicable(packet, logger)

    # parse a trigger not using gas
    trigger = actions.trigger.Trigger.parse("TCP:flags:SA")
    assert trigger.is_applicable(packet, logger)
    # Check that adding gas while gas is disabled does not work
    trigger.add_gas(10)
    assert trigger.gas_remaining == None

    trigger.enable_gas()
    trigger.set_gas(2)

    assert trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)

    # Test that it can handle leading/trailing []
    trigger = actions.trigger.Trigger.parse("[TCP:flags:SA]")
    assert trigger.is_applicable(packet, logger)


def test_bomb_trigger_parse_gas():
    """
    Tests bomb triggers having gas, including changing that gas while in use
    """
    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))

    # parse a bomb trigger with 1 gas
    trigger = actions.trigger.Trigger.parse("TCP:flags:SA:-1")
    assert not trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)

    # parse a trigger with no gas left
    trigger = actions.trigger.Trigger.parse("TCP:flags:SA:0")
    assert not trigger.is_applicable(packet, logger)

    trigger = actions.trigger.Trigger.parse("TCP:flags:SA:-1")
    assert not trigger.is_applicable(packet, logger)

    # parse a trigger not using gas
    trigger = actions.trigger.Trigger.parse("TCP:flags:SA")
    assert trigger.is_applicable(packet, logger)
    # Check that adding gas while gas is disabled does not work
    trigger.add_gas(10)
    assert trigger.gas_remaining == None

    trigger.enable_gas()
    trigger.set_gas(2)

    assert trigger.is_applicable(packet, logger)
    assert trigger.is_applicable(packet, logger)
    assert not trigger.is_applicable(packet, logger)

    # Test that it can handle leading/trailing []
    trigger = actions.trigger.Trigger.parse("[TCP:flags:SA]")
    assert trigger.is_applicable(packet, logger)
