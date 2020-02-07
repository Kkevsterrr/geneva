"""
TamperAction

One of the four packet-level primitives supported by Geneva. Responsible for any packet-level
modifications (particularly header modifications). It supports the following primitives:
 - no operation: it returns the packet given
 - replace: it changes a packet field to a fixed value
 - corrupt: it changes a packet field to a randomly generated value each time it is run
 - add: adds a given value to the value in a field
 - compress: performs DNS decompression on the packet (if applicable)
"""

from actions.action import Action
import actions.utils
from actions.layer import DNSLayer

import random
from actions.http import HTTPRequest as HTTPRequest
import urllib.parse

import string

# All supported tamper primitives
SUPPORTED_PRIMITIVES = ["corrupt", "replace", "add", "compress", "insert", "delete"]


class TamperAction(Action):
    """
    Defines the TamperAction for Geneva.
    """
    def __init__(self, environment_id=None, field=None, tamper_type=None, tamper_value=None, tamper_proto="TCP", start_index=None, end_index=None, encoded_payload=None):
        Action.__init__(self, "tamper", "both")
        self.field = field
        self.tamper_value = tamper_value
        self.tamper_proto = actions.utils.string_to_protocol(tamper_proto)
        self.tamper_proto_str = tamper_proto
        self.tamper_type = tamper_type
        self.start_index = start_index
        self.end_index = end_index
        self.encoded_payload = encoded_payload
        if encoded_payload:
            self.decoded_payload = bytes(urllib.parse.unquote(encoded_payload), "UTF-8")

    def tamper(self, packet, logger):
        """
        Edits a given packet according to the action settings.
        """
        
        # Return packet untouched if not applicable
        if not packet.haslayer(self.tamper_proto_str):
            return packet
        
        # Retrieve the old value of the field for logging purposes
        old_value = packet.get(self.tamper_proto_str, self.field)
        
        new_value = self.tamper_value
        # If corrupting the packet field, generate a value for it
        try:
            if self.tamper_type == "corrupt":
                if self.tamper_proto == HTTPRequest:
                    packet = corrupt(packet, self.field, self.start_index, self.end_index)
                    del packet["IP"].chksum
                    del packet["IP"].len
                    del packet["TCP"].chksum
                    del packet["TCP"].dataofs
                    return packet
                else:
                    new_value = packet.gen(self.tamper_proto_str, self.field)
            elif self.tamper_type == "add":
                new_value = int(self.tamper_value) + int(old_value)
            elif self.tamper_type == "compress":
                return packet.dns_decompress(logger)
            elif self.tamper_type == "insert":
                packet = insert(packet, self.field, self.start_index, self.decoded_payload)
                
                del packet["IP"].chksum
                del packet["IP"].len
                del packet["TCP"].chksum
                del packet["TCP"].dataofs
                return packet
            elif self.tamper_type == "replace":
                packet = replace(packet, self.field, self.start_index, self.decoded_payload)

                del packet["IP"].chksum
                del packet["IP"].len
                del packet["TCP"].chksum
                del packet["TCP"].dataofs
                
                return packet
            elif self.tamper_type == "delete":
                packet = delete(packet, self.field, self.start_index, self.end_index)
                return packet

        except NotImplementedError:
            # If a primitive does not support the type of packet given
            return packet
        except Exception:
            # If an unexpected error has occurred
            return packet

        logger.debug("  - Tampering %s field `%s` (%s) by %s (to %s)" %
                     (self.tamper_proto_str, self.field, str(old_value), self.tamper_type, str(new_value)))
        print("about to call set")
        packet.set(self.tamper_proto_str, self.field, new_value)

        return packet

    def run(self, packet, logger):
        """
        The tamper action runs its tamper procedure on the given packet, and
        returns the edited packet down the left branch.

        Nothing is returned to the right branch.
        """
        return self.tamper(packet, logger), None

    def __str__(self):
        """
        Defines string representation for this object.
        """
        s = Action.__str__(self)
        if self.tamper_type == "corrupt":
            if self.tamper_proto == HTTPRequest:
                s += "{%s:%s:%s:%s}" % (self.tamper_proto_str, self.field, self.tamper_type, str(self.start_index) + "-" + str(self.end_index))
            else:
                s += "{%s:%s:%s}" % (self.tamper_proto_str, self.field, self.tamper_type)
        elif self.tamper_type in ["replace", "add", "insert"]:
            if self.tamper_proto == HTTPRequest:
                s += "{%s:%s:%s:%s:%s}" % (self.tamper_proto_str, self.field, self.tamper_type, str(self.start_index), self.encoded_payload)
            else:
                s += "{%s:%s:%s:%s}" % (self.tamper_proto_str, self.field, self.tamper_type, self.tamper_value)
        elif self.tamper_type == "compress":
            s += "{%s:%s:compress}" % ("DNS", "qd", )
        elif self.tamper_type == "delete":
            s += "{%s:%s:%s:%s}" % (self.tamper_proto_str, self.field, self.tamper_type, str(self.start_index) + "-" + str(self.end_index))

        return s

    def parse(self, string, logger):
        """
        Parse out a given string representation of this action and initialize
        this action to those parameters.

        Note that the given logger is a DIFFERENT logger than the logger passed
        to the other functions, and they cannot be used interchangeably. This logger
        is attached to the main GA driver, and is run outside the evaluator. When the
        action is actually run, it's run within the evaluator, which by necessity must
        pass in a different logger.
        """
        # Different tamper actions will have different number of parameters
        # Count the number of params in this given string
        num_parameters = string.count(":")

        # If num_parameters is greater than 4, it's not a valid tamper action
        if num_parameters > 4 or num_parameters < 2:
            msg = "Cannot parse tamper action %s" % string
            logger.error(msg)
            raise Exception(msg)
        params = string.split(":")
        if num_parameters == 4:
            # HTTP replace or insert
            self.tamper_proto_str, self.field, self.tamper_type, self.start_index, self.encoded_payload = params
            self.start_index = int(self.start_index)
            self.tamper_proto = actions.utils.string_to_protocol(self.tamper_proto_str)
            self.decoded_payload = bytes(urllib.parse.unquote(self.encoded_payload), "UTF-8")

        elif num_parameters == 3:
            # HTTP corrupt or delete could be here, check for those first
            self.tamper_proto_str = params[0]
            self.tamper_proto = actions.utils.string_to_protocol(self.tamper_proto_str)
            if self.tamper_proto_str == "HTTPRequest":
                self.field = params[1]
                self.tamper_type = params[2]
                indices = params[3].split('-')
                self.start_index = int(indices[0])
                self.end_index = int(indices[1])
            else:
                self.tamper_proto_str, self.field, self.tamper_type, self.tamper_value = params
                if "options" in self.field:
                    if not self.tamper_value:
                        self.tamper_value = '' # An empty string instead of an empty byte literal
                # tamper_value might be parsed as a string despite being an integer in most cases.
                # Try to parse it out here
                try:
                    if "load" not in self.field:
                        self.tamper_value = int(self.tamper_value)
                except:
                    pass
            
        elif num_parameters == 2:
            self.tamper_proto_str, self.field, self.tamper_type = params
            self.tamper_proto = actions.utils.string_to_protocol(self.tamper_proto_str)

        return True


def insert(packet, header, index, content):
    """
    Helper method to insert content into packet[header][index]
    """
    if header not in packet["HTTPRequest"].fields:
        # TODO: throw some sort of error, this header doesn't exist
        return None

    if index > len(packet["HTTPRequest"].fields[header]):
        # TODO: throw some sort of error, this index is too large
        return None
    packet["HTTPRequest"].fields[header] = packet["HTTPRequest"].fields[header][0:index] \
                            + content + \
                            packet["HTTPRequest"].fields[header][index:]

    return packet

def replace(packet, header, index, content):
    """
    Helper method to replace packet[header][index] with content
    """
    if header not in packet["HTTPRequest"].fields:
        # TODO: throw some sort of error, this header doesn't exist
        return None

    if index+len(content) > len(packet["HTTPRequest"].fields[header]):
        # TODO: throw some sort of error, this index is too large
        return None

    packet["HTTPRequest"].fields[header] = packet["HTTPRequest"].fields[header][0:index] \
                                + content + \
                                packet["HTTPRequest"].fields[header][index+len(content):]
    return packet


def delete(packet, header, start_index, end_index):
    """
    Helper method to remove the characters at header[start_index] to header[end_index]
    """
    if header not in packet["HTTPRequest"].fields:
        # TODO: throw some sort of error, this header doesn't exist
        return None

    if end_index+1 > len(packet["HTTPRequest"].fields[header]):
        # TODO: throw some sort of error, this index is too large
        return None

    packet["HTTPRequest"].fields[header] = packet["HTTPRequest"].fields[header][0:start_index] \
                                + packet["HTTPRequest"].fields[header][end_index+1:]
    return packet

def corrupt(packet, header, start_index, end_index):
    """
    Helper method to remove the characters at header[start_index] to header[end_index]
    """
    print("in cor")
    if header not in packet["HTTPRequest"].fields:
        # TODO: throw some sort of error, this header doesn't exist
        return None

    if end_index+1 > len(packet["HTTPRequest"].fields[header]):
        # TODO: throw some sort of error, this index is too large
        return None
    print("in cor")
    try:
        old_field = packet["HTTPRequest"].fields[header]
        tampered_field = packet["HTTPRequest"].fields[header][0:start_index]

        for i in range(0, end_index - start_index + 1):
            # Ensure we're getting a new character
            new_character = bytes(random.choice(string.printable), "UTF-8")
            while(new_character == old_field[i]):
                new_character = bytes(random.choice(string.printable), "UTF-8")
            tampered_field = tampered_field + new_character

        tampered_field = tampered_field + packet["HTTPRequest"].fields[header][end_index+1:]
        print("settings tampered field to:")
        print(tampered_field)
        packet["HTTPRequest"].fields[header] = bytes(tampered_field, "UTF-8")
    except Exception as e:
        print(e)

    return packet
