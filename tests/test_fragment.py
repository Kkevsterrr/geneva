import pytest
import logging
import sys
# Include the root of the project
sys.path.append("..")

import actions.fragment
import layers.packet
import actions.strategy
import actions.utils
import evolve

from scapy.all import IP, TCP, UDP

logger = logging.getLogger("test")
MAX_UINT = 4294967295

def test_segment(logger):
    """
    Tests the duplicate action primitive.
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    assert str(fragment) == "fragment{tcp:-1:True}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP()/("data"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'da', "Left packet incorrectly fragmented"
    assert packet2["Raw"].load == b"ta", "Right packet incorrectly fragmented"

def test_segment_wrap(logger):
    """
    Tests if segment numbers can wrap around
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    assert str(fragment) == "fragment{tcp:-1:True}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP()/("data"))
    packet["TCP"].seq = MAX_UINT-1
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'da', "Left packet incorrectly fragmented"
    assert packet2["Raw"].load == b"ta", "Right packet incorrectly fragmented"
    assert packet1["TCP"].seq == MAX_UINT-1
    assert packet2["TCP"].seq == 0

def test_segment_wrap2(logger):
    """
    Tests if segment numbers can wrap around testing for off-by-one
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    assert str(fragment) == "fragment{tcp:-1:True}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP()/("data"))
    packet["TCP"].seq = MAX_UINT
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'da', "Left packet incorrectly fragmented"
    assert packet2["Raw"].load == b"ta", "Right packet incorrectly fragmented"
    assert packet1["TCP"].seq == MAX_UINT
    assert packet2["TCP"].seq == 1


def test_segment_wrap3(logger):
    """
    Tests if segment numbers can wrap around testing for off-by-one
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    assert str(fragment) == "fragment{tcp:-1:True}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP()/("data"))
    packet["TCP"].seq = MAX_UINT-2
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'da', "Left packet incorrectly fragmented"
    assert packet2["Raw"].load == b"ta", "Right packet incorrectly fragmented"
    assert packet1["TCP"].seq == MAX_UINT-2
    assert packet2["TCP"].seq == MAX_UINT


def test_segment_reverse(logger):
    """
    Tests the duplicate action primitive in reverse!
    """
    fragment = actions.fragment.FragmentAction(correct_order=False)
    assert str(fragment) == "fragment{tcp:-1:False}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP()/("data"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'ta', "Left packet incorrectly fragmented"
    assert packet2["Raw"].load == b"da", "Right packet incorrectly fragmented"


def test_odd_fragment(logger):
    """
    Tests long IP fragmentation
    """
    fragment = actions.fragment.FragmentAction(correct_order=True, segment=False)
    assert str(fragment) == "fragment{ip:-1:True}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06)/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("dataisodd"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert str(packet1["Raw"].load) != str(packet2["Raw"].load), "Packets were not different"
    assert packet1["Raw"].load == b'\x08\xae\r\x05\x00\x00\x00d', "Left packet incorrectly fragmented"
    assert packet2["Raw"].load == b'\x00\x00\x00dP\x02 \x00e\xc1\x00\x00dataisodd', "Right packet incorrectly fragmented"
    assert packet1["Raw"].load + packet2["Raw"].load == b'\x08\xae\r\x05\x00\x00\x00d\x00\x00\x00dP\x02 \x00e\xc1\x00\x00dataisodd', "Packets fragmentation was incorrect"


def test_custom_fragment(logger):
    """
    Tests IP fragments with custom sized lengths
    """
    fragment = actions.fragment.FragmentAction(correct_order=True, fragsize=3, segment=False)
    assert str(fragment) == "fragment{ip:3:True}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06)/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("thisissomedata"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"
    assert str(packet1["Raw"].load) != str(packet2["Raw"].load), "Packets were not different"
    assert packet1["Raw"].load == b'\x08\xae\r\x05\x00\x00\x00d\x00\x00\x00dP\x02 \x00zp\x00\x00this', "Left packet incorrectly fragmented"
    assert packet2["Raw"].load == b'issomedata', "Right packet incorrectly fragmented"
    assert packet1["Raw"].load + packet2["Raw"].load == b'\x08\xae\r\x05\x00\x00\x00d\x00\x00\x00dP\x02 \x00zp\x00\x00thisissomedata', "Packets fragmentation was incorrect"


def test_reverse_fragment(logger):
    """
    Tests fragmentation with reversed packets
    """
    fragment = actions.fragment.FragmentAction(correct_order=False, fragsize=3, segment=False)
    assert str(fragment) == "fragment{ip:3:False}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06)/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/("thisissomedata"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"
    assert str(packet1["Raw"].load) != str(packet2["Raw"].load), "Packets were not different"
    assert packet2["Raw"].load == b'\x08\xae\r\x05\x00\x00\x00d\x00\x00\x00dP\x02 \x00zp\x00\x00this', "Left packet incorrectly fragmented"
    assert packet1["Raw"].load == b'issomedata', "Right packet incorrectly fragmented"
    assert packet2["Raw"].load + packet1["Raw"].load == b'\x08\xae\r\x05\x00\x00\x00d\x00\x00\x00dP\x02 \x00zp\x00\x00thisissomedata', "Packets fragmentation was incorrect"


def test_udp_fragment(logger):
    """
    Tests fragmentation with reversed packets
    """
    fragment = actions.fragment.FragmentAction(correct_order=False, fragsize=2, segment=False)
    assert str(fragment) == "fragment{ip:2:False}", "Fragment returned incorrect string representation: %s" % str(fragment)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06)/UDP(sport=2222, dport=3333, chksum=0x4444)/("thisissomedata"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"
    assert str(packet1["Raw"].load) != str(packet2["Raw"].load), "Packets were not different"


def test_mutate(logger):
    """
    Tests mutating the fragment action
    """
    fragment = actions.fragment.FragmentAction(correct_order=False, fragsize=2, segment=False)
    assert str(fragment) == "fragment{ip:2:False}", "Fragment returned incorrect string representation: %s" % str(fragment)

    for _ in range(0, 200):
        fragment.mutate()
        fragment.parse(str(fragment), logger)
        packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06)/TCP(sport=2222, dport=3333, chksum=0x4444)/("thisissomedata"))
        packet1, packet2 = fragment.run(packet, logger)


def test_parse(logger):
    """
    Tests parsing.
    """
    fragment = actions.fragment.FragmentAction(correct_order=False, fragsize=2, segment=False)
    assert str(fragment) == "fragment{ip:2:False}", "Fragment returned incorrect string representation: %s" % str(fragment)

    fragment.parse("fragment{tcp:5:False}", logger)
    assert fragment.correct_order == False
    assert fragment.fragsize == 5
    assert fragment.segment == True

    with pytest.raises(Exception):
        fragment.parse("fragment{tcp:5}", logger)

    with pytest.raises(Exception):
        fragment.parse("fragment{tcp:a:True}", logger)

    assert fragment.correct_order == False
    assert fragment.fragsize == 5
    assert fragment.segment == True

    fragment = actions.fragment.FragmentAction()
    assert fragment.correct_order in [True, False]
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))

    strat = actions.utils.parse("[IP:proto:6:0]-tamper{IP:proto:replace:6}(fragment{ip:-1:True}(tamper{TCP:dataofs:replace:8}(duplicate,),tamper{IP:frag:replace:0}),)-| [IP:tos:0:0]-duplicate-| \/", logger)
    strat.act_on_packet(packet, logger)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=2222, dport=3333, chksum=0x4444))
    strat = actions.utils.parse("[IP:proto:6:0]-tamper{IP:proto:replace:6}(fragment{ip:-1:True}(tamper{TCP:dataofs:replace:8}(duplicate,),tamper{IP:frag:replace:0}),)-| [IP:tos:0:0]-duplicate-| \/", logger)
    strat.act_on_packet(packet, logger)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, chksum=0x4444))
    strat = actions.utils.parse("[TCP:urgptr:0]-tamper{TCP:options-altchksumopt:corrupt}(fragment{tcp:-1:True}(tamper{IP:proto:corrupt},tamper{TCP:seq:replace:654077552}),)-| \/", logger)
    strat.act_on_packet(packet, logger)

    strat = actions.utils.parse("[TCP:options-mss:]-tamper{TCP:load:replace:}(fragment{tcp:-1:True},)-| \/", logger)
    strat.act_on_packet(packet, logger)

    strat = actions.utils.parse("[TCP:options-mss:]-tamper{IP:frag:replace:1353}(tamper{TCP:load:replace:}(fragment{tcp:-1:True},),)-| \/", logger)
    strat.act_on_packet(packet, logger)

    strat = actions.utils.parse("[IP:ihl:5]-duplicate-| [TCP:options-mss:]-tamper{IP:frag:replace:1353}(fragment{tcp:-1:True}(tamper{TCP:load:replace:}(fragment{tcp:-1:False},),tamper{DNSQR:qtype:replace:45416}),)-| \/", logger)
    strat.act_on_packet(packet, logger)

    strat = actions.utils.parse("[DNSQR:qclass:25989]-duplicate(duplicate(tamper{DNSQR:qtype:replace:30882},),tamper{UDP:sport:replace:42042})-| [TCP:options-nop:]-tamper{TCP:options-nop:corrupt}(tamper{TCP:load:replace:mjkuskjzgy}(tamper{IP:frag:replace:410}(fragment{tcp:-1:True},),),)-| \/", logger)
    strat.act_on_packet(packet, logger)


def test_fallback(logger):
    """
    Tests fallback behavior.
    """
    fragment = actions.fragment.FragmentAction(correct_order=False, fragsize=2, segment=False)
    assert str(fragment) == "fragment{ip:2:False}", "Fragment returned incorrect string representation: %s" % str(fragment)

    fragment.parse("fragment{ip:0:False}", logger)
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06)/UDP(sport=2222, dport=3333, chksum=0x4444)/("thisissomedata"))
    packet1, packet2 = fragment.run(packet, logger)
    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"
    assert str(packet1) == str(packet2)

    fragment.parse("fragment{tcp:-1:False}", logger)
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06)/UDP(sport=2222, dport=3333, chksum=0x4444)/("thisissomedata"))
    packet1, packet2 = fragment.run(packet, logger)
    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"
    assert str(packet1) == str(packet2)

    fragment.parse("fragment{tcp:-1:False}", logger)
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06)/TCP(sport=2222, dport=3333, chksum=0x4444))
    packet1, packet2 = fragment.run(packet, logger)
    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"
    assert str(packet1) == str(packet2)

    fragment.parse("fragment{ip:-1:False}", logger)
    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1", proto=0x06))
    packet1, packet2 = fragment.run(packet, logger)
    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"
    assert str(packet1) == str(packet2)


def test_ip_only_fragment(logger):
    """
    Tests fragmentation without higher protocols.
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    fragment.parse("fragment{ip:-1:True}", logger)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/("datadata11datadata"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'datadata', "Left packet incorrectly fragmented"
    assert packet2["Raw"].load == b"11datadata", "Right packet incorrectly fragmented"


def test_overlapping_segment():
    """
    Basic test for overlapping segments.
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    fragment.parse("fragment{tcp:-1:True:4}", logger)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(seq=100)/("datadata11datadata"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'datadata11dat', "Left packet incorrectly segmented"
    assert packet2["Raw"].load == b"1datadata", "Right packet incorrectly fragmented"

    assert packet1["TCP"].seq == 100, "First packet sequence number incorrect"
    assert packet2["TCP"].seq == 109, "Second packet sequence number incorrect"

def test_overlapping_segment_no_overlap():
    """
    Basic test for overlapping segments with no overlap. (shouldn't ever actually happen)
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    fragment.parse("fragment{tcp:-1:True:0}", logger)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(seq=100)/("datadata11datadata"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'datadata1', "Left packet incorrectly segmented"
    assert packet2["Raw"].load == b"1datadata", "Right packet incorrectly fragmented"

    assert packet1["TCP"].seq == 100, "First packet sequence number incorrect"
    assert packet2["TCP"].seq == 109, "Second packet sequence number incorrect"

def test_overlapping_segment_entire_packet():
    """
    Basic test for overlapping segments overlapping entire packet.
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    fragment.parse("fragment{tcp:-1:True:9}", logger)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(seq=100)/("datadata11datadata"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'datadata11datadata', "Left packet incorrectly segmented"
    assert packet2["Raw"].load == b"1datadata", "Right packet incorrectly fragmented"

    assert packet1["TCP"].seq == 100, "First packet sequence number incorrect"
    assert packet2["TCP"].seq == 109, "Second packet sequence number incorrect"

def test_overlapping_segment_out_of_bounds():
    """
    Basic test for overlapping segments overlapping beyond the edge of the packet.
    """
    fragment = actions.fragment.FragmentAction(correct_order=True)
    fragment.parse("fragment{tcp:-1:True:20}", logger)

    packet = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(seq=100)/("datadata11datadata"))
    packet1, packet2 = fragment.run(packet, logger)

    assert id(packet1) != id(packet2), "Duplicate aliased packet objects"

    assert packet1["Raw"].load != packet2["Raw"].load, "Packets were not different"
    assert packet1["Raw"].load == b'datadata11datadata', "Left packet incorrectly segmented"
    assert packet2["Raw"].load == b"1datadata", "Right packet incorrectly fragmented"

    assert packet1["TCP"].seq == 100, "First packet sequence number incorrect"
    assert packet2["TCP"].seq == 109, "Second packet sequence number incorrect"

def test_overlapping_segmentation_parse():
    """
    Basic test for parsing overlapping segments.
    """

    fragment = actions.fragment.FragmentAction(correct_order=False, fragsize=2, segment=True, overlap=3)
    assert str(fragment) == "fragment{tcp:2:False:3}", "Fragment returned incorrect string representation: %s" % str(fragment)
