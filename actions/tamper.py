"""
TamperAction

One of the four packet-level primitives supported by Geneva. Responsible for any packet-level
modifications (particularly header modifications). It supports replace and corrupt mode -
in replace mode, it changes a packet field to a fixed value; in corrupt mode, it changes a packet
field to a randomly generated value each time it is run.
"""

from actions.action import Action
import actions.utils

import random


class TamperAction(Action):
    """
    Defines the TamperAction for Geneva.
    """
    def __init__(self, environment_id=None, field=None, tamper_type=None, tamper_value=None, tamper_proto="TCP"):
        Action.__init__(self, "tamper", "both")
        self.field = field
        self.tamper_value = tamper_value
        self.tamper_proto = actions.utils.string_to_protocol(tamper_proto)
        self.tamper_proto_str = tamper_proto

        self.tamper_type = tamper_type
        if not self.tamper_type:
            self.tamper_type = random.choice(["corrupt", "replace"])

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
        if self.tamper_type == "corrupt":
            new_value = packet.gen(self.tamper_proto_str, self.field)

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
        elif self.tamper_type in ["replace"]:
            s += "{%s:%s:%s:%s}" % (self.tamper_proto_str, self.field, self.tamper_type, self.tamper_value)

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
