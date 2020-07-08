import copy
import sys
import pytest
import random
# Include the root of the project
sys.path.append("..")

import evolve
import evaluator
import actions.strategy
import layers.packet
import actions.utils
import actions.tamper
import layers.layer
import layers.ip_layer

from scapy.all import IP, TCP, UDP, DNS, DNSQR, sr1


def test_tamper(logger):
    """
    Tests tampering with replace
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
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


def test_tamper_ip(logger):
    """
    Tests tampering with IP
    """
    packet = layers.packet.Packet(IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
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


def test_tamper_udp(logger):
    """
    Tests tampering with UDP
    """
    packet = layers.packet.Packet(IP(src='127.0.0.1', dst='127.0.0.1')/UDP(sport=2222, dport=53))
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


def test_tamper_ip_ident(logger):
    """
    Tests tampering with IP and that the checksum is correctly changed
    """

    packet = layers.packet.Packet(IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
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


@pytest.mark.parametrize("use_canary", [False, True], ids=["without_canary", "with_canary"])
def test_mutate(logger, use_canary):
    """
    Tests the tamper 'replace' primitive.
    """
    logger.setLevel("ERROR")
    canary_id = None
    # Create an evaluator
    if use_canary:
        cmd = [
            "--test-type", "echo",
            "--censor", "censor2",
            "--log", actions.utils.CONSOLE_LOG_LEVEL,
            "--no-skip-empty",
            "--bad-word", "facebook",
            "--output-directory", actions.utils.RUN_DIRECTORY
        ]
        tester = evaluator.Evaluator(cmd, logger)

        canary_id = evolve.run_collection_phase(logger, tester)

    for _ in range(0, 25):
        tamper = actions.tamper.TamperAction(None, field="flags", tamper_type="replace", tamper_value="R", tamper_proto="TCP")

        # Test mutation 200 times to ensure it remains stable
        for _ in range(0, 200):
            tamper._mutate(canary_id)
            tamper2 = actions.tamper.TamperAction(None)
            # Confirm tamper value was properly ._fix()-ed
            val = tamper.tamper_value
            for _ in range(0, 5):
                assert tamper.tamper_value == val, "Tamper value is not stable."
            # Create a test packet to ensure the field/proto choice was safe
            if random.random() < 0.5:
                test_packet = layers.packet.Packet(IP()/TCP())
            else:
                test_packet = layers.packet.Packet(IP()/UDP())

            # Check that tamper can run safely after mutation
            try:
                tamper.run(test_packet, logger)
            except:
                print(str(tamper))
                raise

            tamper._mutate_tamper_type()

            # Test that parsing tamper works - note we have to remove the tamper{} to make a call directly using tamper's parse.
            tamper2.parse(str(tamper)[7:-1], logger)
            assert str(tamper2) == str(tamper)


def test_parse_parameters(logger):
    """
    Tests that tamper properly rejects malformed tamper actions
    """
    with pytest.raises(Exception):
        actions.tamper.TamperAction().parse("this:has:too:many:parameters", logger)
    with pytest.raises(Exception):
        actions.tamper.TamperAction().parse("not:enough", logger)



def test_corrupt(logger):
    """
    Tests the tamper 'corrupt' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="flags", tamper_type="corrupt", tamper_value="R")
    assert tamper.field == "flags", "Tamper action changed fields."
    assert tamper.tamper_type == "corrupt", "Tamper action changed types."
    assert str(tamper) == "tamper{TCP:flags:corrupt}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
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


def test_add(logger):
    """
    Tests the tamper 'add' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="seq", tamper_type="add", tamper_value=10)
    assert tamper.field == "seq", "Tamper action changed fields."
    assert tamper.tamper_type == "add", "Tamper action changed types."
    assert str(tamper) == "tamper{TCP:seq:add:10}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
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


def test_decompress(logger):
    """
    Tests the tamper 'decompress' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="qd", tamper_type="compress", tamper_value=10, tamper_proto="DNS")
    assert tamper.field == "qd", "Tamper action changed fields."
    assert tamper.tamper_type == "compress", "Tamper action changed types."
    assert str(tamper) == "tamper{DNS:qd:compress}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = layers.packet.Packet(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="minghui.ca.")))
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

    packet = layers.packet.Packet(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="maps.google.com")))
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
    packet = layers.packet.Packet(IP()/UDP())
    original = packet.copy()
    tamper.tamper(packet, logger)
    assert packet.packet.summary() == original.packet.summary()

    # Confirm tamper didn't corrupt anything else in the TCP header
    assert confirm_unchanged(packet, original, UDP, [])

    # Confirm tamper didn't corrupt anything else in the IP header
    assert confirm_unchanged(packet, original, IP, [])




def test_corrupt_chksum(logger):
    """
    Tests the tamper 'replace' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="chksum", tamper_type="corrupt", tamper_value="R")
    assert tamper.field == "chksum", "Tamper action changed checksum."
    assert tamper.tamper_type == "corrupt", "Tamper action changed types."
    assert str(tamper) == "tamper{TCP:chksum:corrupt}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
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


def test_corrupt_dataofs(logger):
    """
    Tests the tamper 'replace' primitive.
    """
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S", dataofs="6L"))
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


def test_replace(logger):
    """
    Tests the tamper 'replace' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="flags", tamper_type="replace", tamper_value="R")

    assert tamper.field == "flags", "Tamper action changed fields."
    assert tamper.tamper_type == "replace", "Tamper action changed types."

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
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


def test_init():
    """
    Tests initializing with no parameters
    """
    tamper = actions.tamper.TamperAction(None)
    assert tamper.field
    assert tamper.tamper_proto
    assert tamper.tamper_value is not None


def test_parse_flags(logger):
    """
    Tests the tamper 'replace' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="flags", tamper_type="replace", tamper_value="FRAPUN")
    assert tamper.field == "flags", "Tamper action changed checksum."
    assert tamper.tamper_type == "replace", "Tamper action changed types."
    assert str(tamper) == "tamper{TCP:flags:replace:FRAPUN}", "Tamper returned incorrect string representation: %s" % str(tamper)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    tamper.tamper(packet, logger)
    assert packet[TCP].flags == "FRAPUN", "Tamper failed to change flags."


@pytest.mark.parametrize("test_type", ["parsed", "direct"])
@pytest.mark.parametrize("value", ["EOL", "NOP", "Timestamp", "MSS", "WScale", "SAckOK", "SAck", "Timestamp", "AltChkSum", "AltChkSumOpt", "UTO"])
def test_options(logger, value, test_type):
    """
    Tests tampering options
    """
    if test_type == "direct":
        tamper = actions.tamper.TamperAction(None, field="options-%s" % value.lower(), tamper_type="corrupt", tamper_value=bytes([12]))
    else:
        tamper = actions.tamper.TamperAction(None)
        assert tamper.parse("TCP:options-%s:corrupt" % value.lower(), logger)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    tamper.run(packet, logger)
    opts_dict_lookup = value.lower().replace(" ", "_")

    for optname, optval in packet["TCP"].options:
        if optname == value:
            break
        elif optname == layers.ip_layer.TCPLayer.options_names[opts_dict_lookup]:
            break
    else:
        pytest.fail("Failed to find %s in options" % value)
    assert len(packet["TCP"].options) == 1
    raw_p = bytes(packet)
    assert raw_p, "options broke scapy bytes"
    p2 = layers.packet.Packet(IP(bytes(raw_p)))
    assert p2.haslayer("IP")
    assert p2.haslayer("TCP")
    # EOLs might be added for padding, so just check >= 1
    assert len(p2["TCP"].options) >= 1
    for optname, optval in p2["TCP"].options:
        if optname == value:
            break
        elif optname == layers.ip_layer.TCPLayer.options_names[opts_dict_lookup]:
            break
    else:
        pytest.fail("Failed to find %s in options" % value)


def test_tamper_mutate_compress(logger):
    """
    Tests that compress is handled right if its enabled
    """
    backup = copy.deepcopy(actions.tamper.ACTIVATED_PRIMITIVES)
    actions.tamper.ACTIVATED_PRIMITIVES = ["compress"]
    try:
        tamper = actions.tamper.TamperAction(None)
        assert tamper.parse("TCP:flags:corrupt", logger)
        tamper._mutate_tamper_type()
        assert tamper.tamper_type == "compress"
        assert tamper.tamper_proto_str == "DNS"
        assert tamper.field == "qd"
        packet = layers.packet.Packet(IP()/TCP()/DNS()/DNSQR())
        packet2 = tamper.tamper(packet, logger)
        assert packet2 == packet
    finally:
        actions.tamper.ACTIVATED_PRIMITIVES = backup
