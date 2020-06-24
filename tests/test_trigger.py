import sys
# Include the root of the project
sys.path.append("..")

import layers.packet
import actions.strategy
import actions.tamper
import actions.utils
import evolve

from scapy.all import IP, TCP


def test_mutate():
    """
    Tests the tamper 'replace' primitive.
    """
    trigger = actions.trigger.Trigger("field", "flags", "TCP")
    trigger.mutate(None)


def test_init(logger):
    """
    Tests initialization.
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    trigger = actions.trigger.Trigger(None, None, None)
    trigger.is_applicable(packet, logger)

    actions.trigger.FIXED_TRIGGER = actions.trigger.Trigger.parse("TCP:flags:SA")
    assert actions.trigger.Trigger.get_rand_trigger("test", 1) == ("field", "TCP", "flags", "SA", None)


def test_trigger_gas(logger):
    """
    Tests triggers having gas, including changing that gas while in use
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))
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


def test_bomb_trigger_gas(logger):
    """
    Tests triggers having bomb gas, including changing that gas while in use
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))
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


def test_trigger_parse_gas(logger):
    """
    Tests triggers having gas, including changing that gas while in use
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))


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

def test_bomb_trigger_parse_gas(logger):
    """
    Tests bomb triggers having gas, including changing that gas while in use
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))

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

def test_wildcard(logger):
    """
    Test wildcard trigger value
    """
    packet_1 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="A"))
    packet_2 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"))
    packet_3 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="RA"))
    packet_4 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="P"))
    trigger = actions.trigger.Trigger("field", "flags", "TCP", trigger_value="A*", gas=None)
    assert trigger.is_applicable(packet_1, logger)
    assert trigger.is_applicable(packet_2, logger)
    assert trigger.is_applicable(packet_3, logger)
    assert not trigger.is_applicable(packet_4, logger)
