import binascii
import copy
import random
import string
import os
import urllib.parse

from scapy.all import IP, RandIP, UDP, DNS, DNSQR, Raw, TCP, fuzz

class Layer():
    """
    Base class defining a Geneva packet layer.
    """
    protocol = None

    def __init__(self, layer):
        """
        Initializes this layer.
        """
        self.layer = layer
        # No custom setter, getters, generators, or parsers are needed by default
        self.setters = {}
        self.getters = {}
        self.generators = {}
        self.parsers = {}

    @classmethod
    def reset_restrictions(cls):
        """
        Resets field restrictions placed on this layer.
        """
        cls.fields = cls._fields

    def get_next_layer(self):
        """
        Given the current layer returns the next layer beneath us.
        """
        if len(self.layer.layers()) == 1:
            return None

        return self.layer[1]

    def get_random(self):
        """
        Retreives a random field and value.
        """
        field = random.choice(self.fields)
        return field, self.get(field)

    def gen_random(self):
        """
        Generates a random field and value.
        """
        assert self.fields, "Layer %s doesn't have any fields" % str(self)
        field = random.choice(self.fields)
        return field, self.gen(field)

    @classmethod
    def name_matches(cls, name):
        """
        Checks if given name matches this layer name.
        """
        return name.upper() == cls.name.upper()

    def get(self, field):
        """
        Retrieves the value from a given field.
        """
        assert field in self.fields
        if field in self.getters:
            return self.getters[field](field)

        # Dual field accessors are fields that require two pieces of information
        # to retrieve them (for example, "options-eol"). These are delimited by
        # a dash "-".
        base = field.split("-")[0]
        if "-" in field and base in self.getters:
            return self.getters[base](field)

        return getattr(self.layer, field)

    def set(self, packet, field, value):
        """
        Sets the value for a given field.
        """
        assert field in self.fields
        base = field.split("-")[0]
        if field in self.setters:
             self.setters[field](packet, field, value)

        # Dual field accessors are fields that require two pieces of information
        # to retrieve them (for example, "options-eol"). These are delimited by
        # a dash "-".
        elif "-" in field and base in self.setters:
            self.setters[base](packet, field, value)
        else:
            setattr(self.layer, field, value)

        # Request the packet be reparsed to confirm the value is stable
        # XXX Temporarily disabling the reconstitution check due to scapy bug (#2034)
        #assert bytes(self.protocol(bytes(self.layer))) == bytes(self.layer)

    def gen(self, field):
        """
        Generates a value for this field.
        """
        assert field in self.fields
        if field in self.generators:
            return self.generators[field](field)

        # Dual field accessors are fields that require two pieces of information
        # to retrieve them (for example, "options-eol"). These are delimited by
        # a dash "-".
        base = field.split("-")[0]
        if "-" in field and base in self.generators:
            return self.generators[base](field)

        sample = fuzz(self.protocol())

        new_value = getattr(sample, field)
        if new_value == None:
            new_value = 0
        elif type(new_value) != int:
            new_value = new_value._fix()

        return new_value

    def parse(self, field, value):
        """
        Parses the given value for a given field. This is useful for fields whose
        value cannot be represented in a string type easily - it lets us define
        a common string representation for the strategy, and parse it back into
        a real value here.
        """
        assert field in self.fields
        if field in self.parsers:
            return self.parsers[field](field, value)

        # Dual field accessors are fields that require two pieces of information
        # to retrieve them (for example, "options-eol"). These are delimited by
        # a dash "-".
        base = field.split("-")[0]
        if "-" in field and base in self.parsers:
            return self.parsers[base](field, value)

        try:
            parsed = int(value)
        except ValueError:
            parsed = value

        return parsed

    def get_load(self, field):
        """
        Helper method to retrieve load, as scapy doesn't recognize 'load' as
        a regular field properly.
        """
        try:
            load = self.layer.payload.load
        except AttributeError:
            pass
        try:
            load = self.layer.load
        except AttributeError:
            return ""

        if not load:
            return ""

        return urllib.parse.quote(load.decode('utf-8', 'ignore'))

    def set_load(self, packet, field, value):
        """
        Helper method to retrieve load, as scapy doesn't recognize 'load' as
        a field properly.
        """
        if packet.haslayer("IP"):
            del packet["IP"].len

        value = urllib.parse.unquote(value)

        value = value.encode('utf-8')
        dns_payload = b"\x009ib\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x08faceface\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01+\x00\x04\xc7\xbf2I\x00\x00)\x02\x00\x00\x00\x00\x00\x00\x00"
        http_payload = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"

        value = value.replace(b"__DNS_REQUEST__", dns_payload)
        value = value.replace(b"__HTTP_REQUEST__", http_payload)

        self.layer.payload = Raw(value)

    def gen_load(self, field):
        """
        Helper method to generate a random load, as scapy doesn't recognize 'load'
        as a field properly.
        """
        load = ''.join([random.choice(string.ascii_lowercase + string.digits) for k in range(10)])
        return random.choice(["", "__DNS_REQUEST__", "__HTTP_REQUEST__", urllib.parse.quote(load)])
