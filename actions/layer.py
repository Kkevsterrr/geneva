import binascii
import random
import string
import os
import urllib.parse

from scapy.all import IP, RandIP, UDP, Raw, TCP, fuzz

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

        self.layer.payload = Raw(value)

    def gen_load(self, field):
        """
        Helper method to generate a random load, as scapy doesn't recognize 'load'
        as a field properly.
        """
        load = ''.join([random.choice(string.ascii_lowercase + string.digits) for k in range(10)])
        return urllib.parse.quote(load)


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


class TCPLayer(Layer):
    """
    Defines an interface to access TCP header fields.
    """
    name = "TCP"
    protocol = TCP
    _fields = [
        'sport',
        'dport',
        'seq',
        'ack',
        'dataofs',
        'reserved',
        'flags',
        'window',
        'chksum',
        'urgptr',
        'load',
        'options-eol',
        'options-nop',
        'options-mss',
        'options-wscale',
        'options-sackok',
        'options-sack',
        'options-timestamp',
        'options-altchksum',
        'options-altchksumopt',
        'options-md5header',
        'options-uto'
    ]
    fields = _fields

    options_names = {
        "eol": 0,
        "nop": 1,
        "mss": 2,
        "wscale": 3,
        "sackok": 4,
        "sack": 5,
        #"echo" : 6,
        #"echo_reply" : 7,
        "timestamp": 8,
        "altchksum": 14,
        "altchksumopt": 15,
        "md5header": 19,
        #"quick_start" : 27,
        "uto": 28
        #"authentication": 29,
        #"experiment": 254
    }

    # Each entry is Kind: length
    options_length = {
        0: 0, # EOL
        1: 0, # NOP
        2: 2, # MSS
        3: 1, # WScale
        4: 0, # SAckOK
        5: 0, # SAck
        6: 4, # Echo
        7: 4, # Echo Reply
        8: 8, # Timestamp
        14: 3, # AltChkSum
        15: 0, # AltChkSumOpt
        19: 16, # MD5header Option
        27: 6, # Quick-Start response
        28: 2, # User Timeout Option
        29: 4, # TCP Authentication Option
        254: 8, # Experiment

    }
    # Required by scapy
    scapy_options = {
        0: "EOL",
        1: "NOP",
        2: "MSS",
        3: "WScale",
        4: "SAckOK",
        5: "SAck",
        8: "Timestamp",
        14: "AltChkSum",
        15: "AltChkSumOpt",
        28: "UTO",
        # 254:"Experiment" # scapy has two versions of this, so it doesn't work
    }

    def __init__(self, layer):
        """
        Initializes the TCP layer.
        """
        Layer.__init__(self, layer)
        # Special methods to help access fields that cannot be accessed normally
        self.getters = {
            'load' : self.get_load,
            'options' : self.get_options
        }
        self.setters = {
            'load' : self.set_load,
            'options' : self.set_options
        }
        # Special methods to help generate fields that cannot be generated normally
        self.generators = {
            'load' : self.gen_load,
            'dataofs' : self.gen_dataofs,
            'flags'   : self.gen_flags,
            'chksum'  : self.gen_chksum,
            'options' : self.gen_options
        }


    def gen_chksum(self, field):
        """
        Generates a checksum.
        """
        return random.randint(1, 65535)

    def gen_dataofs(self, field):
        """
        Generates a valid value for the data offset field.
        """
        # Dataofs is a 4 bit header, so a max of 15
        return random.randint(1, 15)

    def gen_flags(self, field):
        """
        Generates a random set of flags. 50% of the time it picks randomly from
        a list of real flags, otherwise it returns fuzzed flags.
        """
        if random.random() < 0.5:
            return random.choice(['S', 'A', 'SA', 'PA', 'FA', 'R', 'P', 'F', 'RA', ''])
        else:
            sample = fuzz(self.protocol())
            # Since scapy lazily evaluates fuzzing, we first must set a
            # legitimate value for scapy to evaluate what combination of flags it is
            sample.flags = sample.flags
            return str(sample.flags)

    def get_options(self, field):
        """
        Helper method to retrieve options.
        """
        base, req_option = field.split("-")
        assert base == "options", "get_options can only be used to fetch options."
        option_type = self.option_str_to_int(req_option)
        i = 0
        # First, check if the option is already present in the packet
        for option in self.layer.options:
            # Scapy may try to be helpful and return the string of the option
            next_option = self.option_str_to_int(option[0])
            if option_type == next_option:
                _name, value = self.layer.options[i]
                # Some options (timestamp, checksums, nop) store their value in a
                # tuple.
                if isinstance(value, tuple):
                    # Scapy returns values in any of these types
                    if value in [None, b'', ()]:
                        return ''
                    value = value[0]
                if value in [None, b'', ()]:
                    return ''
                if req_option == "md5header":
                    return binascii.hexlify(value).decode("utf-8")

                return value
            i += 1
        return ''

    def set_options(self, packet, field, value):
        """
        Helper method to set options.
        """
        base, option = field.split("-")
        assert base == "options", "Must use an options field with set_options"

        option_type = self.option_str_to_int(option)
        if type(value) == str:
            # Prepare the value for storage in the packet
            value = binascii.unhexlify(value)

            # Scapy requires these options to be a tuple - since evaling this
            # is not yet supported, for now, SAck will always be an empty tuple
            if option in ["sack"]:
                value = ()
            # These options must be set as integers - if they didn't exist, they can
            # be added like this
            if option in ["timestamp", "mss", "wscale", "altchksum", "uto"] and not value:
                value = 0
        i = 0
        # First, check if the option is already present in the packet
        for option in self.layer.options:
            # Scapy may try to be helpful and return the string of the option
            next_option = self.option_str_to_int(option[0])

            if option_type == next_option:
                packet["TCP"].options[i] = self.format_option(option_type, value)
                break
            i += 1
        # If we didn't break, the option doesn't exist in the packet currently.
        else:
            old_options_array = packet["TCP"].options
            old_options_array.append(self.format_option(option_type, value))
            packet["TCP"].options = old_options_array

        # Let scapy recalculate the required values
        del self.layer.chksum
        del self.layer.dataofs
        if packet.haslayer("IP"):
            del packet["IP"].chksum
            del packet["IP"].len
        return True

    def gen_options(self, field):
        """
        Helper method to set options.
        """
        _, option = field.split("-")
        option_num = self.options_names[option]
        length = self.options_length[option_num]

        data = b''
        if length > 0:
            data = os.urandom(length)
        data = binascii.hexlify(data).decode()
        # MSS must be a 2-byte int
        if option_num == 2:
            data = random.randint(0, 65535)
        # WScale must be a 1-byte int
        elif option_num == 3:
            data = random.randint(0, 255)
        # Timestamp must be an int
        elif option_num == 8:
            data = random.randint(0, 4294967294)
        elif option_num == 14:
            data = random.randint(0, 255)
        elif option_num == 28:
            data = random.randint(0, 255)

        return data

    def option_str_to_int(self, option):
        """
        Takes a string representation of an option and returns the option integer code.
        """
        if type(option) == int:
            return option

        assert "-" not in option, "Must be given specific option: %s." % option

        for val in self.scapy_options:
            if self.scapy_options[val].lower() == option.lower():
                return val

        if " " in option:
            option = option.replace(" ", "_").lower()

        if option.lower() in self.options_names:
            return self.options_names[option.lower()]

    def format_option(self, options_int, value):
        """
        Formats the options so they will work with scapy.
        """
        # NOPs
        if options_int == 1:
            return (self.scapy_options[options_int], ())
        elif options_int in [5]:
            return (self.scapy_options[options_int], value)
        # Timestamp
        elif options_int in [8, 14]:
            return (self.scapy_options[options_int], (value, 0))
        elif options_int in self.scapy_options:
            return (self.scapy_options[options_int], value)
        else:
            return (options_int, value)


class UDPLayer(Layer):
    """
    Defines an interface to access UDP header fields.
    """
    name = "UDP"
    protocol = UDP
    _fields = [
        "sport",
        "dport",
        "chksum",
        "len",
        "load"
    ]
    fields = _fields

    def __init__(self, layer):
        """
        Initializes the UDP layer.
        """
        Layer.__init__(self, layer)
        self.getters = {
            'load' : self.get_load,
        }
        self.setters = {
            'load' : self.set_load,
        }
        self.generators = {
            'load' : self.gen_load,
        }
