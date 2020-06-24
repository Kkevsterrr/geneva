import copy
import sys
import pytest
# Include the root of the project
sys.path.append("..")

import actions.strategy
import actions.utils
import actions.tamper
import layers.layer
import layers.tcp_layer

from scapy.all import IP, TCP, Raw, send


def test_append_options(logger):
    """
    Tests appending a given option
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(tamper_proto="TCP", field="options-wscale", tamper_value=50, tamper_type="replace")
    lpacket, rpacket = tamper.run(packet, logger)
    lpacket.show()
    assert lpacket["TCP"].options == [("WScale", 50)]


def test_append_random_options(logger):
    """
    Tests appending a given option with a random value
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None, field="options-mss", tamper_type="corrupt")
    lpacket, rpacket = tamper.run(packet, logger)
    assert lpacket["TCP"].options[0][0] == 'MSS'
    assert len(lpacket["TCP"].options[0]) == 2

def test_tamper_options(logger):
    """
    Tests tampering a given option with a given value
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None, field="options-timestamp", tamper_type="replace", tamper_value=3433)
    lpacket, rpacket = tamper.run(packet, logger)
    assert lpacket["TCP"].options[0][0] == "Timestamp"
    assert lpacket["TCP"].options[0][1] == (3433, 0)

def test_random_tamper_options(logger):
    """
    Tests tampering a given option with a random value (corrupt)
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None, field="options-mss", tamper_type="corrupt")
    lpacket, rpacket = tamper.run(packet, logger)
    assert lpacket["TCP"].options[0][0] == "MSS"
    if lpacket["TCP"].options[0][1] == 3453:
        lpacket, rpacket = tamper.run(packet, logger)
        assert lpacket["TCP"].options[0][1] != 3453
        # This tests sees if it randomly chooses \xaa\xaa twice, if it did, that'd be amazing (though possible)

def test_correct_assignment(logger):
    """
    Tests that all options can be assigned
    """
    for option in layers.tcp_layer.TCPLayer.scapy_options.values():
        print(option)
        packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
        tamper = actions.tamper.TamperAction(None, field="options-" + str(option.lower()), tamper_type="corrupt")
        lpacket, rpacket = tamper.run(packet, logger)
        assert lpacket["TCP"].options[0][0] == option

def test_str(logger):
    """
    Tests the string representation of each
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))

    tamper = actions.tamper.TamperAction(None, field="options-mss", tamper_value=39584, tamper_type="replace")
    assert str(tamper) == "tamper{TCP:options-mss:replace:39584}"

def test_parse(logger):
    """
    Tests the ability to parse
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None, field="options-mss")
    assert tamper.parse("TCP:options-mss:corrupt", logger)
    assert str(tamper) == "tamper{TCP:options-mss:corrupt}"

def test_parse_run(logger):
    """
    Tests the ability to parse
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None)
    assert tamper.parse("TCP:options-mss:corrupt", logger)

    lpacket, rpacket = tamper.run(packet, logger)
    assert lpacket["TCP"].options[0][1] != 0

def test_parse_num(logger):
    """
    Tests parsing integers
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None, tamper_type="options")
    assert tamper.parse("TCP:options-mss:replace:1440", logger)

    lpacket, rpacket = tamper.run(packet, logger)
    assert lpacket["TCP"].options[0][1] == 1440

def test_option_8(logger):
    """
    Tests options 7
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None)
    assert tamper.parse("TCP:options-timestamp:replace:40000", logger)

    lpacket, rpacket = tamper.run(packet, logger)
    assert lpacket["TCP"].options[0][1] == (40000, 0)

def test_option_1(logger):
    """
    Tests option 1
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None, tamper_type="options")
    assert tamper.parse("TCP:options-nop:corrupt", logger)

    lpacket, rpacket = tamper.run(packet, logger)
    assert lpacket["TCP"].options[0][1] == ()

def test_md5options(logger):
    """
    Tests appending a given option - the md5header
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("data"))
    tamper = actions.tamper.TamperAction(None, field="options-md5header", tamper_value=b'\xee\xee\xee\xee\xee\xee\xee\xee', tamper_type="replace")
    lpacket, rpacket = tamper.run(packet, logger)
    assert lpacket["TCP"].options == [(19, b'\xee\xee\xee\xee\xee\xee\xee\xee')]
