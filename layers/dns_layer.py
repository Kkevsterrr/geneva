import random
from layers.layer import Layer
from scapy.all import DNS

class DNSLayer(Layer):
    """
    Defines an interface to access DNS header fields.
    """
    name = "DNS"
    protocol = DNS
    _fields = [
        "id",
        "qr",
        "opcode",
        "aa",
        "tc",
        "rd",
        "ra",
        "z",
        "ad",
        "cd",
        "qd",
        "rcode",
        "qdcount",
        "ancount",
        "nscount",
        "arcount"
    ]
    fields = _fields
    def __init__(self, layer):
        """
        Initializes the DNS layer.
        """
        Layer.__init__(self, layer)

        self.getters = {
            "qr" : self.get_bitfield,
            "aa" : self.get_bitfield,
            "tc" : self.get_bitfield,
            "rd" : self.get_bitfield,
            "ra" : self.get_bitfield,
            "z"  : self.get_bitfield,
            "ad" : self.get_bitfield,
            "cd" : self.get_bitfield
        }

        self.setters = {
            "qr" : self.set_bitfield,
            "aa" : self.set_bitfield,
            "tc" : self.set_bitfield,
            "rd" : self.set_bitfield,
            "ra" : self.set_bitfield,
            "z"  : self.set_bitfield,
            "ad" : self.set_bitfield,
            "cd" : self.set_bitfield
        }

        self.generators = {
            "id" : self.gen_id,
            "qr" : self.gen_bitfield,
            "opcode" : self.gen_opcode,
            "aa" : self.gen_bitfield,
            "tc" : self.gen_bitfield,
            "rd" : self.gen_bitfield,
            "ra" : self.gen_bitfield,
            "z"  : self.gen_bitfield,
            "ad" : self.gen_bitfield,
            "cd" : self.gen_bitfield,
            "rcode" : self.gen_rcode,
            "qdcount" : self.gen_count,
            "ancount" : self.gen_count,
            "nscount" : self.gen_count,
            "arcount" : self.gen_count
        }

    def get_bitfield(self, field):
        """"""
        return int(getattr(self.layer, field))

    def set_bitfield(self, packet, field, value):
        """"""
        return setattr(self.layer, field, int(value))

    def gen_bitfield(self, field):
        """"""
        return random.choice([0,1])

    def gen_id(self, field):
        return random.randint(0, 65535)

    def gen_opcode(self, field):
        return random.randint(0, 15)

    def gen_rcode(self, field):
        return random.randint(0, 15)

    def gen_count(self, field):
        return random.randint(0, 65535)

    @staticmethod
    def dns_decompress(packet, logger):
        """
        Performs DNS decompression on the given scapy packet, if applicable.
        Note that DNS compression/decompression must be done on the boundaries
        of a label, so DNS compression does not support arbitrary offsets.
        """
        # If this is a TCP packet
        if packet.haslayer("TCP"):
            raise NotImplementedError

        # Perform no action if this is not a DNS or DNSRQ packet
        if not packet.haslayer("DNS") or not packet.haslayer("DNSQR"):
            return packet

        # Extract the query from the DNSQR layer
        query = packet["DNSQR"].qname.decode()
        if query[len(query) - 1] != '.':
            query += '.'

        # Split the query by label
        labels = query.split(".")

        # Collect the first and second half of the query
        fhalf = labels[0]
        shalf = ".".join(labels[1:])

        # Build the first DNS query directly. The format of this a byte string like this:
        # b'\x07minghui\xc0\x1a\x00\x01\x00\x01'
        # \x07     = the length of the label in this DNSQR
        # minghui  = the portion of the domain we will request in the first DNSQR
        # \xc0\x1a = offset into the DNS packet where the rest of the query will be. The actual offset
        #            here is the \x1a - DNS mandates that if compression is used, the first two bits be 11
        #            to differentiate them from the rest. \x1A = 26, which is the length of the DNS header
        #            plus the length of this DNSQR.
        # \x00\x01 = type A record
        # \x00\x01 = IN
        length = bytes([len(fhalf)])
        label = fhalf.encode()

        # Since the domain will include an extra ".", add 1
        # 2 * 6 is the DNS header
        # 1 is the byte that determines the length of the label
        # len(label) is the length of the label
        # 2 is the offset pointer
        # 4 - other record information (class, IN)
        packet_offset = 2 * 6 + 1 + len(label) + 2 + 2 + 2

        # The word must start with binary 11, so OR the offset with 0xC000.
        offset = (0xc000 | packet_offset).to_bytes(2, byteorder='big')
        request = b'\x00\x01\x00\x01'

        dns_qr1 = length + label + offset + request

        # Build the second DNS query directly. The format of the byte string is the same as above
        # b'\x02ca\x00\x00\x01\x00\x01'
        # \x02     = length of the remaining domain
        # ca       = portion of the domain in this DNSQR
        # \x00     = null byte to signify the end of the query
        # \x00\x01 = type A record
        # \x00\x01 = IN
        # Since the second half could potentially contain many labels, this is done in a list comprehension
        dns_qr2 = b"".join([bytes([len(tld)]) + tld.encode() for tld in shalf.split(".")]) + b"\x00\x01\x00\x01"

        # Next, we must rebuild the DNS packet itself. If we try to have scapy parse either dns_qr1 or dns_qr2, they
        # will look malformed, since neither contains a complete request. Therefore, we must build the entire
        # DNS packet at once. First, we must remove the original DNSQR, since this contains the original request
        del packet["DNS"].qd

        # Once the DNSQR is removed, scapy automatically sets the qdcount to 0. Adjust it to 2
        packet["DNS"].qdcount = 2

        # Extract the DNS header standalone now for building
        dns_header = bytes(packet["DNS"])

        dns_packet = DNS(dns_header + dns_qr1 + dns_qr2)

        del packet["DNS"]
        packet = packet / dns_packet

        # Since the size and data of the packet have changed, force scapy to recalculate the important fields
        # in below layers, if applicable
        if packet.haslayer("IP"):
            del packet["IP"].chksum
            del packet["IP"].len
        if packet.haslayer("UDP"):
            del packet["UDP"].chksum
            del packet["UDP"].len

        return packet