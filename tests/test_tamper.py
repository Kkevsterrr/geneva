import copy
import logging
import sys
import pytest
import random
# Include the root of the project
sys.path.append("..")

import actions.strategy
import actions.packet
import actions.utils
import actions.tamper
import actions.layer

from scapy.all import IP, TCP, UDP, DNS, DNSQR, sr1


logger = logging.getLogger("test")


def test_tamper():
    """
    Tests tampering with replace
    """
    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    original = copy.deepcopy(packet)
    tamper = actions.tamper.TamperAction(None, field="flags", tamper_type="replace", tamper_value="R")
    lpacket, rpacket = tamper.run(packet, logger)
    assert not rpacket, "Tamper must not return right child"
    assert lpacket, "Tamper must give a left child"
    assert id(lpacket) == id(packet), "Tamper must edit in place"

    # Confirm tamper replaced the field it was supposed to
    assert packet[TCP].flags == "R", "Tamper did not replace flags."
    new_value = packet[TCP].flags

    # Must run this check repeatedly - if a scapy fuzz-ed value is not properly
    # ._fix()-ed, it will return different values each time it's requested
    for _ in range(0, 5):
        assert packet[TCP].flags == new_value, "Replaced value is not stable"

    # Confirm tamper didn't corrupt anything else in the TCP header
    assert confirm_unchanged(packet, original, TCP, ["flags"])

    # Confirm tamper didn't corrupt anything in the IP header
    assert confirm_unchanged(packet, original, IP, [])


def test_tamper_ip():
    """
    Tests tampering with IP
    """
    packet = actions.packet.Packet(IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    original = copy.deepcopy(packet)
    tamper = actions.tamper.TamperAction(None, field="src", tamper_type="replace", tamper_value="192.168.1.1", tamper_proto="IP")
    lpacket, rpacket = tamper.run(packet, logger)
    assert not rpacket, "Tamper must not return right child"
    assert lpacket, "Tamper must give a left child"
    assert id(lpacket) == id(packet), "Tamper must edit in place"

    # Confirm tamper replaced the field it was supposed to
    assert packet[IP].src == "192.168.1.1", "Tamper did not replace flags."

    # Confirm tamper didn't corrupt anything in the TCP header
    assert confirm_unchanged(packet, original, TCP, [])

    # Confirm tamper didn't corrupt anything else in the IP header
    assert confirm_unchanged(packet, original, IP, ["src"])


def test_tamper_udp():
    """
    Tests tampering with UDP
    """
    packet = actions.packet.Packet(IP(src='127.0.0.1', dst='127.0.0.1')/UDP(sport=2222, dport=53))
    original = copy.deepcopy(packet)
    tamper = actions.tamper.TamperAction(None, field="chksum", tamper_type="replace", tamper_value=4444, tamper_proto="UDP")
    lpacket, rpacket = tamper.run(packet, logger)
    assert not rpacket, "Tamper must not return right child"
    assert lpacket, "Tamper must give a left child"
    assert id(lpacket) == id(packet), "Tamper must edit in place"

    # Confirm tamper replaced the field it was supposed to
    assert packet[UDP].chksum == 4444, "Tamper did not replace flags."

    # Confirm tamper didn't corrupt anything in the TCP header
    assert confirm_unchanged(packet, original, UDP, ["chksum"])

    # Confirm tamper didn't corrupt anything else in the IP header
    assert confirm_unchanged(packet, original, IP, [])


def test_tamper_ip_ident():
    """
    Tests tampering with IP and that the checksum is correctly changed
    """

    packet = actions.packet.Packet(IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    original = copy.deepcopy(packet)
    tamper = actions.tamper.TamperAction(None, field='id', tamper_type='replace', tamper_value=3333, tamper_proto="IP")
    lpacket, rpacket = tamper.run(packet, logger)
    assert not rpacket, "Tamper must not return right child"
    assert lpacket, "Tamper must give a left child"
    assert id(lpacket) == id(packet), "Tamper must edit in place"

    # Confirm tamper replaced the field it was supposed to
    assert packet[IP].id == 3333, "Tamper did not replace flags."

    # Confirm tamper didn't corrupt anything in the TCP header
    assert confirm_unchanged(packet, original, TCP, [])

    # Confirm tamper didn't corrupt anything else in the IP header
    assert confirm_unchanged(packet, original, IP, ["id"])


def confirm_unchanged(packet, original, protocol, changed):
    """
    Checks that no other field besides the given array of changed fields
    are different between these two packets.
    """
    for header in packet.layers:
        if packet.layers[header].protocol != protocol:
            continue
        for field in packet.layers[header].fields:
            # Skip checking the field we just changed
            if field in changed or field == "load":
                continue
            assert packet.get(protocol.__name__, field) == original.get(protocol.__name__, field), "Tamper changed %s field %s." % (str(protocol), field)
    return True


def test_parse_parameters():
    """
    Tests that tamper properly rejects malformed tamper actions
    """
    with pytest.raises(Exception):
        actions.tamper.TamperAction().parse("this:has:too:many:parameters", logger)
    with pytest.raises(Exception):
        actions.tamper.TamperAction().parse("not:enough", logger)


def test_corrupt():
    """
    Tests the tamper 'corrupt' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="flags", tamper_type="corrupt", tamper_value="R")
    assert tamper.field == "flags", "Tamper action changed fields."
    assert tamper.tamper_type == "corrupt", "Tamper action changed types."
    assert str(tamper) == "tamper{TCP:flags:corrupt}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    original = copy.deepcopy(packet)
    tamper.tamper(packet, logger)

    new_value = packet[TCP].flags

    # Must run this check repeatedly - if a scapy fuzz-ed value is not properly
    # ._fix()-ed, it will return different values each time it's requested
    for _ in range(0, 5):
        assert packet[TCP].flags == new_value, "Corrupted value is not stable"

    # Confirm tamper didn't corrupt anything else in the TCP header
    assert confirm_unchanged(packet, original, TCP, ["flags"])

    # Confirm tamper didn't corrupt anything else in the IP header
    assert confirm_unchanged(packet, original, IP, [])


def test_add():
    """
    Tests the tamper 'add' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="seq", tamper_type="add", tamper_value=10)
    assert tamper.field == "seq", "Tamper action changed fields."
    assert tamper.tamper_type == "add", "Tamper action changed types."
    assert str(tamper) == "tamper{TCP:seq:add:10}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    original = copy.deepcopy(packet)
    tamper.tamper(packet, logger)

    new_value = packet[TCP].seq
    assert new_value == 110, "Tamper did not add"

    # Must run this check repeatedly - if a scapy fuzz-ed value is not properly
    # ._fix()-ed, it will return different values each time it's requested
    for _ in range(0, 5):
        assert packet[TCP].seq == new_value, "Corrupted value is not stable"

    # Confirm tamper didn't corrupt anything else in the TCP header
    assert confirm_unchanged(packet, original, TCP, ["seq"])

    # Confirm tamper didn't corrupt anything else in the IP header
    assert confirm_unchanged(packet, original, IP, [])


def test_decompress():
    """
    Tests the tamper 'decompress' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="qd", tamper_type="compress", tamper_value=10, tamper_proto="DNS")
    assert tamper.field == "qd", "Tamper action changed fields."
    assert tamper.tamper_type == "compress", "Tamper action changed types."
    assert str(tamper) == "tamper{DNS:qd:compress}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = actions.packet.Packet(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="minghui.ca.")))
    original = packet.copy()
    tamper.tamper(packet, logger)
    assert bytes(packet["DNS"]) == b'\x00\x00\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x07minghui\xc0\x1a\x00\x01\x00\x01\x02ca\x00\x00\x01\x00\x01'
    resp = sr1(packet.packet)
    assert resp["DNS"]
    assert resp["DNS"].rcode != 1
    assert resp["DNSQR"]
    assert resp["DNSRR"].rdata
    assert confirm_unchanged(packet, original, IP, ["len"])
    print(resp.summary())

    packet = actions.packet.Packet(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="maps.google.com")))
    original = packet.copy()
    tamper.tamper(packet, logger)
    assert bytes(packet["DNS"]) == b'\x00\x00\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x04maps\xc0\x17\x00\x01\x00\x01\x06google\x03com\x00\x00\x01\x00\x01'
    resp = sr1(packet.packet)
    assert resp["DNS"]
    assert resp["DNS"].rcode != 1
    assert resp["DNSQR"]
    assert resp["DNSRR"].rdata
    assert confirm_unchanged(packet, original, IP, ["len"])
    print(resp.summary())

    # Confirm this is a NOP on normal packets
    packet = actions.packet.Packet(IP()/UDP())
    original = packet.copy()
    tamper.tamper(packet, logger)
    assert packet.packet.summary() == original.packet.summary()

    # Confirm tamper didn't corrupt anything else in the TCP header
    assert confirm_unchanged(packet, original, UDP, [])

    # Confirm tamper didn't corrupt anything else in the IP header
    assert confirm_unchanged(packet, original, IP, [])

    packet = actions.packet.Packet(IP(dst="8.8.8.8")/TCP(dport=53)/DNS(qd=DNSQR(qname="maps.google.com")))
    original = packet.copy()
    tamper.tamper(packet, logger)
    assert bytes(packet) == bytes(original)



def test_corrupt_chksum():
    """
    Tests the tamper 'replace' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="chksum", tamper_type="corrupt", tamper_value="R")
    assert tamper.field == "chksum", "Tamper action changed checksum."
    assert tamper.tamper_type == "corrupt", "Tamper action changed types."
    assert str(tamper) == "tamper{TCP:chksum:corrupt}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    original = copy.deepcopy(packet)
    tamper.tamper(packet, logger)

    # Confirm tamper actually corrupted the checksum
    assert packet[TCP].chksum != 0
    new_value = packet[TCP].chksum

    # Must run this check repeatedly - if a scapy fuzz-ed value is not properly
    # ._fix()-ed, it will return different values each time it's requested
    for _ in range(0, 5):
        assert packet[TCP].chksum == new_value, "Corrupted value is not stable"

    # Confirm tamper didn't corrupt anything else in the TCP header
    assert confirm_unchanged(packet, original, TCP, ["chksum"])

    # Confirm tamper didn't corrupt anything else in the IP header
    assert confirm_unchanged(packet, original, IP, [])


def test_corrupt_dataofs():
    """
    Tests the tamper 'replace' primitive.
    """
    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S", dataofs="6L"))
    original = copy.deepcopy(packet)
    tamper = actions.tamper.TamperAction(None, field="dataofs", tamper_type="corrupt")

    tamper.tamper(packet, logger)

    # Confirm tamper actually corrupted the checksum
    assert packet[TCP].dataofs != "0"
    new_value = packet[TCP].dataofs

    # Must run this check repeatedly - if a scapy fuzz-ed value is not properly
    # ._fix()-ed, it will return different values each time it's requested
    for _ in range(0, 5):
        assert packet[TCP].dataofs == new_value, "Corrupted value is not stable"

    # Confirm tamper didn't corrupt anything else in the TCP header
    assert confirm_unchanged(packet, original, TCP, ["dataofs"])

    # Confirm tamper didn't corrupt anything in the IP header
    assert confirm_unchanged(packet, original, IP, [])


def test_replace():
    """
    Tests the tamper 'replace' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="flags", tamper_type="replace", tamper_value="R")

    assert tamper.field == "flags", "Tamper action changed fields."
    assert tamper.tamper_type == "replace", "Tamper action changed types."

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    original = copy.deepcopy(packet)
    tamper.tamper(packet, logger)

    # Confirm tamper replaced the field it was supposed to
    assert packet[TCP].flags == "R", "Tamper did not replace flags."
    # Confirm tamper didn't replace anything else in the TCP header
    assert confirm_unchanged(packet, original, TCP, ["flags"])

    # Confirm tamper didn't replace anything else in the IP header
    assert confirm_unchanged(packet, original, IP, [])

    # chksums must be handled specially by tamper, so run a second check on this value
    tamper.field = "chksum"
    tamper.tamper_value = 0x4444
    original = copy.deepcopy(packet)
    tamper.tamper(packet, logger)
    assert packet[TCP].chksum == 0x4444, "Tamper failed to change chksum."
    # Confirm tamper didn't replace anything else in the TCP header
    assert confirm_unchanged(packet, original, TCP, ["chksum"])
    # Confirm tamper didn't replace anything else in the IP header
    assert confirm_unchanged(packet, original, IP, [])


def test_parse_flags():
    """
    Tests the tamper 'replace' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="flags", tamper_type="replace", tamper_value="FRAPUN")
    assert tamper.field == "flags", "Tamper action changed checksum."
    assert tamper.tamper_type == "replace", "Tamper action changed types."
    assert str(tamper) == "tamper{TCP:flags:replace:FRAPUN}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    tamper.tamper(packet, logger)
    assert packet[TCP].flags == "FRAPUN", "Tamper failed to change flags."


@pytest.mark.parametrize("test_type", ["parsed", "direct"])
@pytest.mark.parametrize("value", ["EOL", "NOP", "Timestamp", "MSS", "WScale", "SAckOK", "SAck", "Timestamp", "AltChkSum", "AltChkSumOpt", "UTO"])
def test_options(value, test_type):
    """
    Tests tampering options
    """
    if test_type == "direct":
        tamper = actions.tamper.TamperAction(None, field="options-%s" % value.lower(), tamper_type="corrupt", tamper_value=bytes([12]))
    else:
        tamper = actions.tamper.TamperAction(None)
        assert tamper.parse("TCP:options-%s:replace:" % value.lower(), logger)
        assert tamper.parse("TCP:options-%s:corrupt" % value.lower(), logger)

    packet = actions.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    tamper.run(packet, logger)
    opts_dict_lookup = value.lower().replace(" ", "_")

    for optname, optval in packet["TCP"].options:
        if optname == value:
            break
        elif optname == actions.layer.TCPLayer.options_names[opts_dict_lookup]:
            break
    else:
        pytest.fail("Failed to find %s in options" % value)
    assert len(packet["TCP"].options) == 1
    raw_p = bytes(packet)
    assert raw_p, "options broke scapy bytes"
    p2 = actions.packet.Packet(IP(bytes(raw_p)))
    assert p2.haslayer("IP")
    assert p2.haslayer("TCP")
    # EOLs might be added for padding, so just check >= 1
    assert len(p2["TCP"].options) >= 1
    for optname, optval in p2["TCP"].options:
        if optname == value:
            break
        elif optname == actions.layer.TCPLayer.options_names[opts_dict_lookup]:
            break
    else:
        pytest.fail("Failed to find %s in options" % value)
