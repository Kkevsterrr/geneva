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
from layers.dns_layer import DNSLayer

import random


# All supported tamper primitives
SUPPORTED_PRIMITIVES = ["corrupt", "replace", "add", "compress"]

# Tamper primitives we can mutate to by default
ACTIVATED_PRIMITIVES = ["replace", "corrupt"]


class TamperAction(Action):
    """
    Defines the TamperAction for Geneva.
    """
    frequency = 5
    def __init__(self, environment_id=None, field=None, tamper_type=None, tamper_value=None, tamper_proto="TCP"):
        """
        Creates a tamper object.

        Args:
            environment_id (str, optional): environment_id of a previously run strategy, used to find packet captures
            field (str, optional): field that the object will tamper. If not set, all the parameters are chosen randomly
            tamper_type (str, optional): primitive this tamper will use ("corrupt")
            tamper_value (str, optional): value to tamper to
            tamper_proto (str, optional): protocol we are tampering
        """
        Action.__init__(self, "tamper", "both")
        self.field = field
        self.tamper_value = tamper_value
        self.tamper_proto = actions.utils.string_to_protocol(tamper_proto)
        self.tamper_proto_str = tamper_proto

        self.tamper_type = tamper_type
        if not self.tamper_type:
            self._mutate_tamper_type()

        if not self.field:
            self._mutate(environment_id)

    def mutate(self, environment_id=None):
        """
        Mutate can switch between the tamper type, field.
        """
        # With some probability switch tamper types
        pick = random.random()
        if pick < 0.2:
           self._mutate_tamper_type()
        else:
            self._mutate(environment_id)

    def _mutate_tamper_type(self):
        """
        Randomly picks a tamper type to change to.
        """
        self.tamper_type = random.choice(ACTIVATED_PRIMITIVES)
        if self.tamper_type == "compress":
            self.tamper_proto_str = "DNS"
            self.tamper_proto = actions.utils.string_to_protocol(self.tamper_proto_str)
            self.field = "qd"

    def _mutate(self, environment_id):
        """
        Mutates this action using:
         - previously seen packets with 50% probability
         - a fuzzed packet with 50% probability
        """
        # Retrieve a new protocol and field options for this protocol
        proto, field, value = actions.utils.get_from_fuzzed_or_real_packet(environment_id, 0.5)
        self.tamper_proto = proto
        self.tamper_proto_str = proto.__name__
        self.field = field
        self.tamper_value = value

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
                new_value = packet.gen(self.tamper_proto_str, self.field)
            elif self.tamper_type == "add":
                new_value = int(self.tamper_value) + int(old_value)
            elif self.tamper_type == "compress":
                return packet.dns_decompress(logger)
        except NotImplementedError:
            # If a primitive does not support the type of packet given
            return packet
        except Exception:
            # If an unexpected error has occurred
            return packet

        logger.debug("  - Tampering %s field `%s` (%s) by %s (to %s)" %
                     (self.tamper_proto_str, self.field, str(old_value), self.tamper_type, str(new_value)))

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
            s += "{%s:%s:%s}" % (self.tamper_proto_str, self.field, self.tamper_type)
        elif self.tamper_type in ["replace", "add"]:
            s += "{%s:%s:%s:%s}" % (self.tamper_proto_str, self.field, self.tamper_type, self.tamper_value)
        elif self.tamper_type == "compress":
            s += "{%s:%s:compress}" % ("DNS", "qd", )

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

        # If num_parameters is greater than 3, it's not a valid tamper action
        if num_parameters > 3 or num_parameters < 2:
            msg = "Cannot parse tamper action %s" % string
            logger.error(msg)
            raise Exception(msg)
        params = string.split(":")
        if num_parameters == 3:
            self.tamper_proto_str, self.field, self.tamper_type, self.tamper_value = params
            self.tamper_proto = actions.utils.string_to_protocol(self.tamper_proto_str)
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
        else:
            self.tamper_proto_str, self.field, self.tamper_type = params
            self.tamper_proto = actions.utils.string_to_protocol(self.tamper_proto_str)

        return True
