import random

from layers.layer import Layer
from scapy.all import IP, fuzz, RandIP

class IPLayer(Layer):
    """
    Defines an interface to access IP header fields.
    """
    name = "IP"
    protocol = IP
    _fields = [
        'version',
        'ihl',
        'tos',
        'len',
        'id',
        'flags',
        'frag',
        'ttl',
        'proto',
        'chksum',
        'src',
        'dst',
        'load'
    ]
    fields = _fields

    def __init__(self, layer):
        """
        Initializes the IP layer.
        """
        Layer.__init__(self, layer)
        self.getters = {
            "flags" : self.get_flags,
            "load"  : self.get_load
        }
        self.setters = {
            "flags" : self.set_flags,
            "load"  : self.set_load
        }
        self.generators = {
            "src"    : self.gen_ip,
            "dst"    : self.gen_ip,
            "chksum" : self.gen_chksum,
            "len"    : self.gen_len,
            "load"   : self.gen_load,
            "flags"  : self.gen_flags
        }

    def gen_len(self, field):
        """
        Generates a valid IP length. Scapy breaks if the length is set to 0, so
        return a random int starting at 1.
        """
        return random.randint(1, 500)

    def gen_chksum(self, field):
        """
        Generates a checksum.
        """
        return random.randint(1, 65535)

    def gen_ip(self, field):
        """
        Generates an IP address.
        """
        return RandIP()._fix()

    def get_flags(self, field):
        """
        Retrieves flags as a string.
        """
        return str(self.layer.flags)

    def set_flags(self, packet, field, value):
        """
        Sets the flags field. There is a bug in scapy, if you retrieve an empty
        flags field, it will return "", but you cannot set this value back.
        To reproduce this bug:

        .. code-block:: python

           >>> setattr(IP(), "flags", str(IP().flags)) # raises a ValueError

        To handle this case, this method converts empty string to zero so that
        it can be safely stored.
        """
        if value == "":
            value = 0
        self.layer.flags = value

    def gen_flags(self, field):
        """
        Generates random valid flags.
        """
        sample = fuzz(self.protocol())

        # Since scapy lazily evaluates fuzzing, we first must set a
        # legitimate value for scapy to evaluate what combination of flags it is
        sample.flags = sample.flags

        return str(sample.flags)