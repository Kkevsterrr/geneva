import actions.utils
import random
import re
import layers.packet

FIXED_TRIGGER = None
GAS_ENABLED = True

class Trigger(object):
    def __init__(self, trigger_type, trigger_field, trigger_proto, trigger_value=0, environment_id=None, gas=None):
        """
        Params:
            - trigger_type: the type of trigger. Only "field" (matching based on a field value) is currently supported.
            - trigger_field: the field the trigger should check in a packet to trigger on
            - trigger_proto: the protocol the trigger should look in to retrieve the trigger field
            - trigger_value: the value in the trigger_field that, upon a match, will cause the trigger to fire
            - environment_id: environment_id the current trigger is running under. Used to retrieve previously saved packets
            - gas: how many times this trigger can fire before it stops triggering. gas=None disables gas (unlimited triggers.)
            - has_wildcard: represents if the trigger will match a specific value, or any value containing trigger_value
        """
        self.trigger_type = trigger_type
        self.trigger_field = trigger_field
        self.trigger_proto = trigger_proto
        self.trigger_value = trigger_value
        self.environment_id = environment_id
        self.num_seen = 0
        self.gas_remaining = gas
        self.has_wildcard = False
        # Bomb triggers act like reverse triggers. They run the action only after the action has been triggered x times
        self.bomb_trigger = bool(gas and gas < 0)
        self.ran = False
        # ignore numerical trigger values
        if isinstance(self.trigger_value, (str)):
            # check if value field is wildcarded or not
            if(len(self.trigger_value) != 0 and self.trigger_value[-1] == '*'):
                self.has_wildcard = True
                # remove '*' wildcard from trigger_value for ease of use
                self.trigger_value = self.trigger_value[:-1]
        if not self.trigger_type:
            self.trigger_type, self.trigger_proto, self.trigger_field, self.trigger_value, self.gas_remaining = Trigger.get_rand_trigger(environment_id, 1)

    @staticmethod
    def get_gas():
        """
        Returns a random value for gas for this trigger.
        """
        if GAS_ENABLED and random.random() < 0.2:
            # Use gas in 20% of scenarios
            # Pick a number for gas between 0 - 5
            gas_remaining = int(random.random() * 5)
        else:
            # Do not use gas
            gas_remaining = None
        return gas_remaining

    @staticmethod
    def get_rand_trigger(environment_id, real_packet_probability):
        """
        Creates a random trigger.
        """
        proto, field, value = actions.utils.get_from_fuzzed_or_real_packet(environment_id, real_packet_probability, enable_options=False, enable_load=False)
        gas_remaining = Trigger.get_gas()
        if not FIXED_TRIGGER:
            # Only "field" triggers are supported currently
            return "field", proto.__name__, field, value, gas_remaining
        return (FIXED_TRIGGER.trigger_type,
                FIXED_TRIGGER.trigger_proto,
                FIXED_TRIGGER.trigger_field,
                FIXED_TRIGGER.trigger_value,
                FIXED_TRIGGER.gas_remaining)

    def mutate(self, environment_id, real_packet_probability=0.5):
        """
        Mutates this trigger object by picking a new protocol, field, and value.
        """
        self.trigger_type, self.trigger_proto, self.trigger_field, self.trigger_value, self.gas_remaining = Trigger.get_rand_trigger(environment_id, real_packet_probability)

    def is_applicable(self, packet, logger):
        """
        Checks if this trigger is applicable to a given packet.
        """
        will_run = False
        self.num_seen += 1
        if not packet.haslayer(self.trigger_proto):
            return False

        packet_value = packet.get(self.trigger_proto, self.trigger_field)
        if self.has_wildcard:
            will_run = (self.trigger_value in packet_value)
        else:
            will_run = (self.trigger_value == packet_value)

        # Track if this action is used
        if (not GAS_ENABLED or self.gas_remaining is None) and will_run:
            self.ran = True
        # If this is a normal trigger and we are out of gas, do not run
        elif not self.bomb_trigger and will_run and self.gas_remaining == 0:
            will_run = False
        # If this is a bomb trigger, run once gas hits zero
        elif self.bomb_trigger and will_run and self.gas_remaining == 0:
            self.ran = True
        # If this is a normal trigger and we still have gas remaining, run and
        # decrement the gas
        elif will_run and self.gas_remaining > 0:
            # Gas is enabled and we haven't run out yet, subtract one from our gas
            self.gas_remaining -= 1
            self.ran = True
        # A bomb trigger has negative gas - it does not allow the action to run until the trigger
        # matches x times
        elif will_run and self.gas_remaining < 0:
            self.gas_remaining += 1
            will_run = False

        return will_run

    def __str__(self):
        """
        Returns a string representation of this trigger in the form:
        <protocol>:<field>:<value>:<gas remaining>
        or
        <protocol>:<field>:<value>
        """
        if self.gas_remaining is not None:
            return str(self.trigger_proto)+":"+str(self.trigger_field)+":"+str(self.trigger_value)+":"+str(self.gas_remaining)
        else:
            return str(self.trigger_proto)+":"+str(self.trigger_field)+":"+str(self.trigger_value)

    def add_gas(self, gas):
        """
        Adds gas to this trigger, gas is an integer
        """
        if self.gas_remaining is not None:
            self.gas_remaining += gas

    def set_gas(self, gas):
        """
        Sets the gas to the specified value
        """
        self.gas_remaining = gas

    def disable_gas(self):
        """
        Disables the use of gas.
        """
        self.gas_remaining = None

    def enable_gas(self):
        """
        Sets gas to 0
        """
        self.gas_remaining = 0

    @staticmethod
    def parse(string):
        """
        Given a string representation of a trigger, define a new Trigger represented
        by this string.
        """
        if string:
            string = string.strip()
        if string and string.startswith("["):
            string = string[1:]
        if string and string.endswith("]"):
            string = string[:-1]

        # Trigger is currently a 4-way data tuple of pieces separated by a ":"
        m = re.match("(\S*):(\S*):(\S*):(\S*)", string)
        has_gas = True
        if not m:
            has_gas = False
            m = re.match("(\S*):(\S*):(\S*)", string)
            if not m:
                return None

        trigger_type = "field"
        proto = m.group(1)
        field = m.group(2)
        value = m.group(3)

        # Parse out the given value if necessary
        value = layers.packet.Packet.parse(proto, field, value)

        # Trigger gas is set to None if it is disabled
        trigger_gas = None
        if has_gas:
            trigger_gas = int(m.group(4))

        # Define the new trigger with these parameters
        t = Trigger(trigger_type, field, proto, value, gas=trigger_gas)
        return t
