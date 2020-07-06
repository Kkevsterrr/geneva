from layers.layer import Layer
from scapy.all import DNSQR

class DNSQRLayer(Layer):
    """
    Defines an interface to access DNSQR header fields.
    """
    name = "DNSQR"
    protocol = DNSQR
    _fields = [
        "qname",
        "qtype",
        "qclass"
    ]
    fields = _fields

    def __init__(self, layer):
        """
        Initializes the DNS layer.
        """
        Layer.__init__(self, layer)
        self.getters = {
            "qname" : self.get_qname
        }
        self.generators = {
            "qname" : self.gen_qname
        }

    def get_qname(self, field):
        """
        Returns decoded qname from packet.
        """
        return self.layer.qname.decode('utf-8')

    def gen_qname(self, field):
        """
        Generates domain name.
        """
        return "example.com."

    @classmethod
    def name_matches(cls, name):
        """
        Scapy returns the name of DNSQR as _both_ DNSQR and "DNS Question Record",
        which breaks parsing. Override the name_matches method to handle that case
        here.
        """
        return name.upper() in ["DNSQR", "DNS QUESTION RECORD"]
