import pytest

import actions.utils
import actions.trigger
import layers.packet
import layers.layer
import layers.tcp_layer
import layers.dns_layer
import layers.dnsqr_layer
import layers.udp_layer
import layers.ip_layer
import evolve

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, DNSRR


def test_parse_layers():
    """
    Tests layer parsing.
    """
    pkt = IP()/TCP()/Raw("")
    packet = layers.packet.Packet(pkt)
    layers_l = list(packet.read_layers())
    assert layers_l[0].name == "IP"
    assert layers_l[1].name == "TCP"

    layers_dict = packet.setup_layers()
    assert layers_dict["IP"]
    assert layers_dict["TCP"]


def test_get_random():
    """
    Tests get random
    """

    tcplayer = layers.tcp_layer.TCPLayer(TCP())
    field, value = tcplayer.get_random()
    assert field in layers.tcp_layer.TCPLayer.fields


def test_gen_random():
    """
    Tests gen random
    """
    for i in range(0, 2000):
        layer, field, value = layers.packet.Packet().gen_random()
        assert layer in [DNS, TCP, UDP, IP, DNSQR]


def test_dnsqr():
    """
    Tests DNSQR.
    """
    pkt = UDP()/DNS(ancount=1)/DNSQR()
    pkt.show()
    packet = layers.packet.Packet(pkt)
    packet.show()
    assert len(packet.layers) == 3
    assert "UDP" in packet.layers
    assert "DNS" in packet.layers
    assert "DNSQR" in packet.layers
    pkt = IP()/UDP()/DNS()/DNSQR()
    packet = layers.packet.Packet(pkt)
    assert str(packet)


def test_load():
    """
    Tests loads.
    """
    tcp = layers.tcp_layer.TCPLayer(TCP())
    load = tcp.gen("load")
    pkt = IP()/"datadata"
    p = layers.packet.Packet(pkt)
    assert p.get("IP", "load") == "datadata"
    p2 = layers.packet.Packet(IP(bytes(p)))
    assert p2.get("IP", "load") == "datadata"
    p2.set("IP", "load", "data2")
    # Check p is unchanged
    assert p.get("IP", "load") == "datadata"
    assert p2.get("IP", "load") == "data2"
    p2.show2()
    # Check that we can dump
    assert p2.show2(dump=True)
    # Check that we can dump
    assert p2.show(dump=True)
    assert p2.get("IP", "chksum") == None

    pkt = IP()/TCP()/"datadata"
    p = layers.packet.Packet(pkt)
    assert p.get("TCP", "load") == "datadata"
    p2 = layers.packet.Packet(IP(bytes(p)))
    assert p2.get("TCP", "load") == "datadata"
    p2.set("TCP", "load", "data2")
    # Check p is unchanged
    assert p.get("TCP", "load") == "datadata"
    assert p2.get("TCP", "load") == "data2"
    p2.show2()
    assert p2.get("IP", "chksum") == None


def test_parse_load(logger):
    """
    Tests load parsing.
    """
    pkt = layers.packet.Packet(IP()/TCP()/"TYPE A\r\n")
    print("Parsed: %s" % pkt.get("TCP", "load"))

    strat = actions.utils.parse("[TCP:load:TYPE%20A%0D%0A]-drop-| \/", logger)
    results = strat.act_on_packet(pkt, logger)
    assert not results

    value = pkt.gen("TCP", "load") + " " + pkt.gen("TCP", "load")
    pkt.set("TCP", "load", value)
    assert " " not in pkt.get("TCP", "load"), "%s contained a space!" % pkt.get("TCP", "load")


def test_dns():
    """
    Tests DNS layer.
    """
    dns = layers.dns_layer.DNSLayer(DNS())
    print(dns.gen("id"))
    assert dns.gen("id")

    p = layers.packet.Packet(DNS(id=0xabcd))
    p2 = layers.packet.Packet(DNS(bytes(p)))
    assert p.get("DNS", "id") == 0xabcd
    assert p2.get("DNS", "id") == 0xabcd

    p2.set("DNS", "id", 0x4321)
    assert p.get("DNS", "id") == 0xabcd # Check p is unchanged
    assert p2.get("DNS", "id") == 0x4321

    dns = layers.packet.Packet(DNS(aa=1))
    assert dns.get("DNS", "aa") == 1
    aa = dns.gen("DNS", "aa")
    assert aa == 0 or aa == 1
    assert dns.get("DNS", "aa") == 1 # Original value unchanged

    dns = layers.packet.Packet(DNS(opcode=15))
    assert dns.get("DNS", "opcode") == 15
    opcode = dns.gen("DNS", "opcode")
    assert opcode >= 0 and opcode <= 15
    assert dns.get("DNS", "opcode") == 15 # Original value unchanged

    dns.set("DNS", "opcode", 3)
    assert dns.get("DNS", "opcode") == 3

    dns = layers.packet.Packet(DNS(qr=0))
    assert dns.get("DNS", "qr") == 0
    qr = dns.gen("DNS", "qr")
    assert qr == 0 or qr == 1
    assert dns.get("DNS", "qr") == 0 # Original value unchanged

    dns.set("DNS", "qr", 1)
    assert dns.get("DNS", "qr") == 1

    dns = layers.packet.Packet(DNS(arcount=0xAABB))
    assert dns.get("DNS", "arcount") == 0xAABB
    arcount = dns.gen("DNS", "arcount")
    assert arcount >= 0 and arcount <= 0xffff
    assert dns.get("DNS", "arcount") == 0xAABB # Original value unchanged

    dns.set("DNS", "arcount", 65432)
    assert dns.get("DNS", "arcount") == 65432

    dns = layers.dns_layer.DNSLayer(DNS()/DNSQR(qname="example.com"))
    assert isinstance(dns.get_next_layer(), DNSQR)
    print(dns.gen("id"))
    assert dns.gen("id")

    p = layers.packet.Packet(DNS(id=0xabcd))
    p2 = layers.packet.Packet(DNS(bytes(p)))
    assert p.get("DNS", "id") == 0xabcd
    assert p2.get("DNS", "id") == 0xabcd


def test_read_layers():
    """
    Tests the ability to read each layer
    """
    packet = IP() / UDP() / TCP() / DNS() / DNSQR(qname="example.com") / DNSQR(qname="example2.com") / DNSQR(qname="example3.com")
    packet_geneva = layers.packet.Packet(packet)
    packet_geneva.setup_layers()

    i = 0
    for layer in packet_geneva.read_layers():
        if i == 0:
            assert isinstance(layer, layers.ip_layer.IPLayer)
        elif i == 1:
            assert isinstance(layer, layers.udp_layer.UDPLayer)
        elif i == 2:
            assert isinstance(layer, layers.tcp_layer.TCPLayer)
        elif i == 3:
            assert isinstance(layer, layers.dns_layer.DNSLayer)
        elif i == 4:
            assert isinstance(layer, layers.dnsqr_layer.DNSQRLayer)
            assert layer.layer.qname == b"example.com"
        elif i == 5:
            assert isinstance(layer, layers.dnsqr_layer.DNSQRLayer)
            assert layer.layer.qname == b"example2.com"
        elif i == 6:
            assert isinstance(layer, layers.dnsqr_layer.DNSQRLayer)
            assert layer.layer.qname == b"example3.com"
        i += 1

def test_multi_opts():
    """
    Tests various option getting/setting.
    """
    pkt = IP()/TCP(options=[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (4154603075, 0)), ('NOP', None), ('WScale', 7), ('md5header', b'abcd' * 8)])
    packet = layers.packet.Packet(pkt)
    assert packet.get("TCP", "options-sackok") == ''
    assert packet.get("TCP", "options-mss") == 1460
    assert packet.get("TCP", "options-timestamp") == 4154603075
    assert packet.get("TCP", "options-wscale") == 7
    packet.set("TCP", "options-timestamp", 400000000)
    assert packet.get("TCP", "options-sackok") == ''
    assert packet.get("TCP", "options-mss") == 1460
    assert packet.get("TCP", "options-timestamp") == 400000000
    assert packet.get("TCP", "options-wscale") == 7
    pkt = IP()/TCP(options=[('SAckOK', b''), ('Timestamp', (4154603075, 0)), ('NOP', None), ('WScale', 7)])
    packet = layers.packet.Packet(pkt)
    # If the option isn't present, it will be returned as an empty string
    assert packet.get("TCP", "options-mss") == ''
    packet.set("TCP", "options-mss", "")
    assert packet.get("TCP", "options-mss") == 0


def test_options_eol():
    """
    Tests options-eol.
    """
    pkt = TCP(options=[("EOL", None)])
    p = layers.packet.Packet(pkt)
    assert p.get("TCP", "options-eol") == ""
    p2 = layers.packet.Packet(TCP(bytes(p)))
    assert p2.get("TCP", "options-eol") == ""
    p = layers.packet.Packet(IP()/TCP(options=[]))
    assert p.get("TCP", "options-eol") == ""
    p.set("TCP", "options-eol", "")
    p.show()
    assert len(p["TCP"].options) == 1
    assert any(k == "EOL" for k, v in p["TCP"].options)
    value = p.gen("TCP", "options-eol")
    assert value == "", "eol cannot store data"
    p.set("TCP", "options-eol", value)
    p2 = TCP(bytes(p))
    assert any(k == "EOL" for k, v in p2["TCP"].options)


def test_compression_fallback(logger):
    """
    Test that compression does not touch a packet without DNS in it packet
    """
    pkt = UDP()
    p = layers.packet.Packet(pkt)
    p2 = layers.dns_layer.DNSLayer.dns_decompress(p, logger)
    assert p2 == p, "dns_decompress changed a non DNS packet"


def test_options_mss():
    """
    Tests options-eol.
    """
    pkt = TCP(options=[("MSS", 1440)])
    p = layers.packet.Packet(pkt)
    assert p.get("TCP", "options-mss") == 1440
    p2 = layers.packet.Packet(TCP(bytes(p)))
    assert p2.get("TCP", "options-mss") == 1440
    p = layers.packet.Packet(TCP(options=[]))
    assert p.get("TCP", "options-mss") == ""
    p.set("TCP", "options-mss", 2880)
    p.show()
    assert len(p["TCP"].options) == 1
    assert any(k == "MSS" for k, v in p["TCP"].options)
    value = p.gen("TCP", "options-mss")
    p.set("TCP", "options-mss", value)
    p2 = TCP(bytes(p))
    assert any(k == "MSS" for k, v in p2["TCP"].options)


def check_get(protocol, field, value):
    """
    Checks if the get method worked for this protocol, field, and value.
    """
    pkt = protocol()
    setattr(pkt, field, value)
    packet = layers.packet.Packet(pkt)
    assert packet.get(protocol.__name__, field) == value


def get_test_configs():
    """
    Generates test configurations for the getters.
    """
    return [
        (IP, 'version', 4),
        (IP, 'version', 6),
        (IP, 'version', 0),
        (IP, 'ihl', 0),
        (IP, 'tos', 0),
        (IP, 'len', 50),
        (IP, 'len', 6),
        (IP, 'flags', 'MF'),
        (IP, 'flags', 'DF'),
        (IP, 'flags', 'MF+DF'),
        (IP, 'ttl', 25),
        (IP, 'proto', 4),
        (IP, 'chksum', 0x4444),
        (IP, 'src', '127.0.0.1'),
        (IP, 'dst', '127.0.0.1'),
        (TCP, 'sport', 12345),
        (TCP, 'dport', 55555),
        (TCP, 'seq', 123123123),
        (TCP, 'ack', 181818181),
        (TCP, 'dataofs', 5),
        (TCP, 'dataofs', 0),
        (TCP, 'dataofs', 15),
        (TCP, 'reserved', 0),
        (TCP, 'window', 100),
        (TCP, 'chksum', 0x4444),
        (TCP, 'urgptr', 1),

        (DNS, 'id', 0xabcd),
        (DNS, 'qr', 1),
        (DNS, 'opcode', 9),
        (DNS, 'aa', 0),
        (DNS, 'tc', 1),
        (DNS, 'rd', 0),
        (DNS, 'ra', 1),
        (DNS, 'z', 0),
        (DNS, 'ad', 1),
        (DNS, 'cd', 0),
        (DNS, 'qdcount', 0x1234),
        (DNS, 'ancount', 12345),
        (DNS, 'nscount', 49870),
        (DNS, 'arcount', 0xABCD),

        (DNSQR, 'qname', 'example.com.'),
        (DNSQR, 'qtype', 1),
        (DNSQR, 'qclass', 0),
    ]


def get_custom_configs():
    """
    Generates test configurations that can use the custom getters.
    """
    return [
        (IP, 'flags', ''),
        (TCP, 'options-eol', ''),
        (TCP, 'options-nop', ''),
        (TCP, 'options-mss', 0),
        (TCP, 'options-mss', 1440),
        (TCP, 'options-mss', 5000),
        (TCP, 'options-wscale', 20),
        (TCP, 'options-sackok', ''),
        (TCP, 'options-sack', ''),
        (TCP, 'options-timestamp', 12345678),
        (TCP, 'options-altchksum', 0x44),
        (TCP, 'options-altchksumopt', ''),
        (TCP, 'options-uto', 1),
        #(TCP, 'options-md5header', 'deadc0ffee')
    ]


@pytest.mark.parametrize("config", get_test_configs(),
    ids=['%s-%s-%s' % (proto.__name__, field, str(val)) for proto, field, val in get_test_configs()])
def test_get(config):
    """
    Tests value retrieval.
    """
    proto, field, val = config
    check_get(proto, field, val)


def check_set_get(protocol, field, value):
    """
    Checks if the get method worked for this protocol, field, and value.
    """
    pkt = layers.packet.Packet(protocol())
    pkt.set(protocol.__name__, field, value)
    assert pkt.get(protocol.__name__, field) == value
    # Rebuild the packet to confirm the type survived
    pkt2 = layers.packet.Packet(protocol(bytes(pkt)))
    assert pkt2.get(protocol.__name__, field) == value, "Value %s for header %s didn't survive packet parsing." % (value, field)


@pytest.mark.parametrize("config", get_test_configs() + get_custom_configs(),
    ids=['%s-%s-%s' % (proto.__name__, field, str(val)) for proto, field, val in get_test_configs() + get_custom_configs()])
def test_set_get(config):
    """
    Tests value retrieval.
    """
    proto, field, value = config
    check_set_get(proto, field, value)


def check_gen_set_get(protocol, field):
    """
    Checks if the get method worked for this protocol, field, and value.
    """
    pkt = layers.packet.Packet(protocol())
    new_value = pkt.gen(protocol.__name__, field)
    pkt.set(protocol.__name__, field, new_value)
    assert pkt.get(protocol.__name__, field) == new_value
    # Rebuild the packet to confirm the type survived
    pkt2 = layers.packet.Packet(protocol(bytes(pkt)))
    assert pkt2.get(protocol.__name__, field) == new_value


@pytest.mark.parametrize("config", get_test_configs() + get_custom_configs(),
    ids=['%s-%s' % (proto.__name__, field) for proto, field, _ in get_test_configs() + get_custom_configs()])
def test_gen_set_get(config):
    """
    Tests value retrieval.
    """
    # Test each generator 50 times to hit a range of values
    for i in range(0, 50):
        proto, field, _ = config
        check_gen_set_get(proto, field)


def test_custom_get():
    """
    Tests value retrieval for custom getters.
    """
    pkt = IP()/TCP()/Raw(load="AAAA")
    tcp = layers.packet.Packet(pkt)
    assert tcp.get("TCP", "load") == "AAAA"


def test_restrict_fields(logger):
    """
    Tests packet field restriction.
    """
    layers.packet.SUPPORTED_LAYERS = [
        layers.ip_layer.IPLayer,
        layers.tcp_layer.TCPLayer,
        layers.udp_layer.UDPLayer
    ]
    tcpfields = layers.tcp_layer.TCPLayer.fields
    udpfields = layers.udp_layer.UDPLayer.fields
    ipfields = layers.ip_layer.IPLayer.fields

    layers.packet.Packet.restrict_fields(logger, ["TCP", "UDP"], [], [])
    assert len(layers.packet.SUPPORTED_LAYERS) == 2
    assert layers.tcp_layer.TCPLayer in layers.packet.SUPPORTED_LAYERS
    assert layers.udp_layer.UDPLayer in layers.packet.SUPPORTED_LAYERS
    assert not layers.ip_layer.IPLayer in layers.packet.SUPPORTED_LAYERS

    pkt = IP()/TCP()
    packet = layers.packet.Packet(pkt)
    assert "TCP" in packet.layers
    assert not "IP" in packet.layers
    assert len(packet.layers) == 1

    for i in range(0, 2000):
        layer, proto, field = layers.packet.Packet().gen_random()
        assert layer in [TCP, UDP]

    # Check we can't retrieve any IP fields
    for field in layers.ip_layer.IPLayer.fields:
        with pytest.raises(AssertionError):
            packet.get("IP", field)

    # Check we can get all the TCP fields
    for field in layers.tcp_layer.TCPLayer.fields:
        packet.get("TCP", field)

    layers.packet.Packet.restrict_fields(logger, ["TCP", "UDP"], ["flags"], [])
    packet = layers.packet.Packet(pkt)
    assert len(layers.packet.SUPPORTED_LAYERS) == 1
    assert layers.tcp_layer.TCPLayer in layers.packet.SUPPORTED_LAYERS
    assert not layers.udp_layer.UDPLayer in layers.packet.SUPPORTED_LAYERS
    assert not layers.ip_layer.IPLayer in layers.packet.SUPPORTED_LAYERS
    assert layers.tcp_layer.TCPLayer.fields == ["flags"]
    assert not layers.udp_layer.UDPLayer.fields

    # Check we can't retrieve any IP fields
    for field in layers.ip_layer.IPLayer.fields:
        with pytest.raises(AssertionError):
            packet.get("IP", field)

    # Check we can get all the TCP fields
    for field in tcpfields:
        if field == "flags":
            packet.get("TCP", field)
        else:
            with pytest.raises(AssertionError):
                packet.get("TCP", field)

    for i in range(0, 2000):
        layer, field, value = layers.packet.Packet().gen_random()
        assert layer == TCP
        assert field == "flags"

        _, proto, field, value, _ = actions.trigger.Trigger.get_rand_trigger(None, 0)
        assert proto == 'TCP'
        assert field == "flags"
    layers.packet.Packet.reset_restrictions()
    layers.packet.SUPPORTED_LAYERS = [
        layers.ip_layer.IPLayer,
        layers.tcp_layer.TCPLayer,
        layers.udp_layer.UDPLayer
    ]

    with pytest.raises(AssertionError):
        layers.packet.Packet.restrict_fields(logger, ["TCP", "IP"], ["notathing"], ["notathing"])
    layers.packet.Packet.reset_restrictions()

    layers.packet.Packet.restrict_fields(logger, ["TCP", "IP"], [], ["sport", "dport", "seq", "src"])
    packet = layers.packet.Packet(pkt)
    packet = packet.copy()
    assert packet.has_supported_layers()
    assert len(layers.packet.SUPPORTED_LAYERS) == 2
    assert layers.tcp_layer.TCPLayer in layers.packet.SUPPORTED_LAYERS
    assert not layers.udp_layer.UDPLayer in layers.packet.SUPPORTED_LAYERS
    assert layers.ip_layer.IPLayer in layers.packet.SUPPORTED_LAYERS
    assert set(layers.tcp_layer.TCPLayer.fields) == set([f for f in tcpfields if f not in ["sport", "dport", "seq"]])
    assert set(layers.ip_layer.IPLayer.fields) == set([f for f in ipfields if f not in ["src"]])

    # Check we can't retrieve any IP fields
    for field in layers.ip_layer.IPLayer.fields:
        if field == "src":
            with pytest.raises(AssertionError):
                packet.get("IP", field)
        else:
            packet.get("IP", field)

    # Check we can get all the TCP fields
    for field in tcpfields:
        if field in ["sport", "dport", "seq"]:
            with pytest.raises(AssertionError):
                packet.get("TCP", field)
        else:
            packet.get("TCP", field)

    for i in range(0, 2000):
        layer, field, value = layers.packet.Packet().gen_random()
        assert layer in [TCP, IP]
        assert field not in ["sport", "dport", "seq", "src"]

        _, proto, field, value, _ = actions.trigger.Trigger.get_rand_trigger(None, 0)
        assert proto in ['TCP', 'IP']
        assert field not in ["sport", "dport", "seq", "src"]

    layers.packet.Packet.reset_restrictions()
    layers.packet.SUPPORTED_LAYERS = [
        layers.ip_layer.IPLayer,
        layers.tcp_layer.TCPLayer,
        layers.udp_layer.UDPLayer
    ]

    evolve.restrict_headers(logger, "ip,udp,dns", "", "version")
    packet = layers.packet.Packet(pkt)
    proto, field, value = packet.get_random()
    assert proto.__name__ in ["IP", "UDP"]
    assert len(layers.packet.SUPPORTED_LAYERS) == 2
    assert not layers.tcp_layer.TCPLayer in layers.packet.SUPPORTED_LAYERS
    assert layers.udp_layer.UDPLayer in layers.packet.SUPPORTED_LAYERS
    assert layers.ip_layer.IPLayer in layers.packet.SUPPORTED_LAYERS
    assert set(layers.ip_layer.IPLayer.fields) == set([f for f in ipfields if f not in ["version"]])
    assert set(layers.udp_layer.UDPLayer.fields) == set(udpfields)

    layers.packet.Packet.reset_restrictions()
    for layer in layers.packet.SUPPORTED_LAYERS:
        assert layer.fields, '%s has no fields - reset failed!' % str(layer)
