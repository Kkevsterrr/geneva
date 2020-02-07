import random

import actions.utils
import actions.tree


class Strategy(object):
    def __init__(self, in_actions, out_actions, environment_id=None):
        self.in_actions = in_actions
        self.out_actions = out_actions
        self.in_enabled = True
        self.out_enabled = True

        self.environment_id = environment_id
        self.fitness = -1000

    def __str__(self):
        """
        Builds a string describing the action trees for this strategy.
        """
        return "%s \/ %s" % (self.str_forest(self.out_actions).strip(), self.str_forest(self.in_actions).strip())

    def __len__(self):
        """
        Returns the number of actions in this strategy.
        """
        num = 0
        for tree in self.in_actions:
            num += len(tree)
        for tree in self.out_actions:
            num += len(tree)
        return num

    def str_forest(self, forest):
        """
        Returns a string representation of a given forest (inbound or outbound)
        """
        rep = ""
        for action_tree in forest:
            rep += "%s " % str(action_tree)
        return rep

    def pretty_print(self):
        return "%s \n \/ \n %s" % (self.pretty_str_forest(self.out_actions), self.pretty_str_forest(self.in_actions))

    def pretty_str_forest(self, forest):
        """
        Returns a string representation of a given forest (inbound or outbound)
        """
        rep = ""
        for action_tree in forest:
            rep += "%s\n" % action_tree.pretty_print()
        return rep

    def act_on_packet(self, packet, logger, direction="out"):
        """
        Runs the strategy on a given scapy packet.
        """
        # If there are no actions to run for this strategy, just send the packet
        if (direction == "out" and not self.out_actions) or \
           (direction == "in" and not self.in_actions):
            return [packet]
        return self.run_on_packet(packet, logger, direction)

    def run_on_packet(self, packet, logger, direction):
        """
        Runs the strategy on a given packet given the forest direction.
        """
        forest = self.out_actions
        if direction == "in":
            forest = self.in_actions

        ran = False
        original_packet = packet.copy()
        packets_to_send = []
        for action_tree in forest:
            if action_tree.check(original_packet, logger):
                logger.debug(" + %s action tree triggered: %s", direction, str(action_tree))
                # If multiple trees run, the previous packet may have been tampered with. Ensure
                # we're always acting on a fresh copy
                fresh_packet = original_packet.copy()
                packets_to_send += action_tree.run(fresh_packet, logger)
                ran = True

        # If no action tree was applicable, send the packet unimpeded
        if not ran:
            packets_to_send = [packet]
        
        return packets_to_send
