"""
Defines an action tree. Action trees are comprised of a trigger and a tree of actions.
"""

import random
import re

import anytree
from anytree.exporter import DotExporter

import actions.utils
import actions.trigger


class ActionTreeParseError(Exception):
    """
    Exception thrown when an action tree is malformed or cannot be parsed.
    """


class ActionTree():
    """
    Defines an ActionTree for the Geneva system.
    """

    def __init__(self, direction, trigger=None):
        """
        Creates this action tree.

        Args:
            direction (str): Direction this tree is facing ("out", "in")
            trigger (:obj:`actions.trigger.Trigger`): Trigger to use with this tree
        """
        self.trigger = trigger
        self.action_root = None
        self.direction = direction
        self.environment_id = None
        self.ran = False

    def initialize(self, num_actions, environment_id, allow_terminal=True, disabled=None):
        """
        Sets up this action tree with a given number of random actions.
        Note that the returned action trees may have less actions than num_actions
        if terminal actions are used.
        """
        self.environment_id = environment_id
        self.trigger = actions.trigger.Trigger(None, None, None, environment_id=environment_id)
        if not allow_terminal or random.random() > 0.1:
            allow_terminal = False

        for _ in range(num_actions):
            new_action = self.get_rand_action(self.direction, disabled=disabled)
            self.add_action(new_action)
        return self

    def __iter__(self):
        """
        Sets up a preoder iterator for the tree.
        """
        for node in self.preorder(self.action_root):
            yield node

    def __getitem__(self, index):
        """
        Implements indexing
        """
        if index > len(self):
            return None
        # Wrap around if given negative number to allow for negative indexing
        if index < 0:
            index = index + len(self)
        idx = 0
        for action in self:
            if idx == index:
                return action
            idx += 1

    def __len__(self):
        """
        Calculates the number of actions in the tree.
        """
        num = 0
        for node in self:
            if node:
                num += 1
        return num

    def __str__(self):
        """
        Returns a string representation for the action tree.
        """
        rep = "[%s]-" % str(self.trigger)
        for string in self.string_repr(self.action_root):
            rep += string
        if not rep.endswith("-"):
            rep += "-"
        rep += "|"
        return rep

    def do_parse(self, node, string, logger):
        """
        Handles the preorder recursive parsing.
        """
        # If we're passed an empty string, return None
        if not string.strip():
            return None

        # If there is no subtree defined here, the action string is the string we've been given,
        # and there are no left or right actions left
        if "(" not in string:
            action_string = string
            left_actions, right_actions = "", ""
        else:
            # Find the outermost (first) occurance of "(" - this defines the boundaries between
            # this current action and it's subtree actions
            subtree_idx = string.find("(")
            # Split this string into the action and it's subtree string
            action_string, rest = string[:subtree_idx], string[subtree_idx:]

            # We need to split the remaining string at the correct comma that splits this subtree's
            # left and right actions. To find the correct comma to split on, we need to find the
            # comma that splits the current tree 'in the middle' - where the depth is the number of
            # splits.  This occurs when we cound the same number of commas as open parenthesis "(".
            depth = 0
            comma = 0
            idx = 0
            for char in rest:
                if char == "(":
                    depth += 1
                if char == ",":
                    comma += 1
                if comma == depth and depth > 0:
                    break
                idx += 1
            # If we did not break, we didn't find where to split. Raise an exception
            else:
                raise ActionTreeParseError("Given string %s is malformed" % string)

            # Split on this index, and ignore the first character "(" and last character ")"
            left_actions, right_actions = rest[1:idx], rest[idx+1:-1]

        # Parse the action_string using action.utils
        action_obj = actions.action.Action.parse_action(action_string, self.direction, logger)
        if not action_obj:
            raise ActionTreeParseError("Did not get a legitimate action object from %s" %
                                       action_string)

        # Assign this action_obj to the node
        node = action_obj

        # Sanity check - if this is not a branching action but it has right actions, raise
        if not node.branching and right_actions:
            raise ActionTreeParseError("Cannot have a non branching action with right subtree")

        # Sanity check = if this is a termainal action but it has sub actions, raise
        if node.terminal and (right_actions or left_actions):
            raise ActionTreeParseError("Cannot have a terminal action with children")

        # If we have a left action and were given a packet to pass on, run
        # on the left packet
        if left_actions:
            node.left = self.do_parse(node.left, left_actions, logger)

        # If we have a left action and were given a packet to pass on, run
        # on the left packet
        if right_actions:
            node.right = self.do_parse(node.right, right_actions, logger)

        return node

    def parse(self, string, logger):
        """
        Parses a string representation of an action tree into this object.
        """
        # Individual action trees always end in "|" to signify the end - refuse
        # to parse if this is malformed
        if not string.strip().endswith("|"):
            msg = "Tree does not end with |. Was I given an entire strategy or part of a tree?"
            logger.error(msg)
            return False

        # The format of each action matches this regular expression. For example, given
        # the action tree: [TCP:flags:SA]-tamper{TCP:flags:corrupt}-|
        # it would parse out the trigger "TCP:flags:SA" and the tree as
        # "-tamper{TCP:flags:corrupt}"
        match = re.match(r"\[(\S*)\]-(\S*)|", string)
        if not match or not match.group(0):
            logger.error("Could not identify trigger or tree")
            return False

        # Ask the trigger class to parse this trigger to define a new object
        trigger = actions.trigger.Trigger.parse(match.group(1))
        # If we couldn't parse the trigger, bail
        if not trigger:
            logger.error("Trigger failed to parse")
            return False
        tree = match.group(2)

        # Depending on the form of the action tree, there might be a hanging "-|" or "|"
        # Remove them
        if tree.endswith("-|"):
            tree = tree.replace("-|", "")
        if tree.endswith("|"):
            tree = tree.replace("|", "")

        # Parse the rest of the tree and setup the action tree
        try:
            self.action_root = self.do_parse(self.action_root, tree, logger)
        except ActionTreeParseError:
            logger.exception("Exception caught from parser")
            return False

        self.trigger = trigger
        return self

    def check(self, packet, logger):
        """
        Checks if this action tree should run on this packet.
        """
        return self.trigger.is_applicable(packet, logger)

    def do_run(self, node, packet, logger):
        """
        Handles recursively running a packet down the tree.
        """
        # If there is no action here, yield None
        if not node:
            yield None
        else:
            # Run this current action against the given packet.
            # It will give us a packet to pass to the left and right child
            left_packet, right_packet = node.run(packet, logger)

            # If there is no left child, yield the left packet
            if not node.left:
                yield left_packet

            # If we have a left action and were given a packet to pass on, run
            # on the left packet
            if node.left and left_packet:
                for lpacket in self.do_run(node.left, left_packet, logger):
                    yield lpacket

            # If there is no right child, yield the right packet
            if not node.right:
                yield right_packet

            # If we have a right action and were given a packet to pass on, run
            # on the right packet
            if node.right and right_packet:
                for rpacket in self.do_run(node.right, right_packet, logger):
                    yield rpacket

    def run(self, packet, logger):
        """
        Runs a packet through the action tree.
        """
        self.ran = True
        packets = []
        for processed in self.do_run(self.action_root, packet, logger):
            if processed:
                packets.append(processed)
        return packets

    def preorder(self, node):
        """
        Yields a preorder traversal of the tree.
        """
        yield node
        if node and node.left:
            for lnode in self.preorder(node.left):
                yield lnode
        if node and node.right:
            for rnode in self.preorder(node.right):
                yield rnode

    def string_repr(self, node):
        """
        Yields a preorder traversal of the tree to create a string representation.
        """
        if not node:
            yield ""
        else:

            yield "%s" % node
            # Only yield a subtree start representation if there is a subtree to build
            if node.left or node.right:
                yield "("

            # Setup the left subtree representation
            if node.left:
                for lnode in self.string_repr(node.left):
                    yield str(lnode)

            # Only yield subtree representation if there is a subtree to build
            if node.left or node.right:
                yield ","

            # Setup the right subtree representation
            if node and node.right:
                for rnode in self.string_repr(node.right):
                    yield str(rnode)

            # Only yield subtree representation if there is a subtree to build
            if node.left or node.right:
                yield ")"

    def remove_action(self, action):
        """
        Removes a given action from the tree.
        """
        # If there is only an action root and no other actions, just delete the root
        if action == self.action_root and not self.action_root.left and not self.action_root.right:
            self.action_root = None
            return True

        # If there is no tree at all, nothing to remove
        if not self.action_root:
            return False

        for node in self:
            # If the node we're removing is the root of the tree, replace it with the left child
            # if it exists; if not, the right child.
            if node == action and action == self.action_root:
                self.action_root = action.left or action.right
                return True
            if node.left == action:
                node.left = action.left
                return True
            if node.right == action:
                node.right = action.left
                return True
        return False

    def get_slots(self):
        """
        Returns the number of locations a new action could be added.
        """
        slots = 0
        for action in self:
            # Terminal actions have no children
            if action.terminal:
                continue
            if not action.left:
                slots += 1
            if not action.right and action.branching:
                slots += 1
        return slots

    def count_leaves(self):
        """
        Counts the number of leaves.
        """
        leaves = 0
        for action in self:
            if not action.left and not action.right:
                leaves += 1
        return leaves

    def contains(self, action):
        """
        Checks if an action is contained in the tree.
        """
        for node in self:
            if node == action:
                return True
        return False

    def add_action(self, new_action):
        """
        Adds an action to this action tree.
        """
        # Refuse to add None actions
        if not new_action:
            return False

        # If no actions are in this tree yet, this given action is the new root
        if not self.action_root:
            self.action_root = new_action
            return True

        # We cannot add an action if it is already in the tree, or we could recurse
        # forever
        if self.contains(new_action):
            return False
        # Count the open spaces that we could put a new action to.
        # This is effectively counting the leaves we could have if all the leaves had children
        slots = self.get_slots()

        # We will visit each available slot and add the action there with probability
        # 1/slots. Since it's possible we could visit every slot without having hit that
        # probability yet, keep iterating until we do.
        action_added = False
        while not action_added and slots > 0:
            for action in self:
                if not action.left and not action.terminal and random.random() < 1/float(slots):
                    action.left = new_action
                    action_added = True
                    break
                # We can only add to the right child if this action can introduce branching,
                # such as (duplicate, fragment)
                if not action.right and not action.terminal and action.branching and \
                        random.random() < 1/float(slots):
                    action.right = new_action
                    action_added = True
                    break
        return action_added

    def get_rand_action(self, direction, request=None, allow_terminal=True, disabled=None):
        """
        Retrieves and initializes a random action that can run in the given direction.
        """
        pick = random.random()
        action_options = actions.action.Action.get_actions(direction, disabled=disabled, allow_terminal=allow_terminal)
        # Check to make sure there are still actions available to use
        assert action_options, "No actions were available"
        act_dict = {}
        all_opts = []
        for action_name, act_cls in action_options:
            act_dict[action_name] = act_cls
            all_opts += ([act_cls] * act_cls.frequency)
        new_action = act_dict.get(request, random.choice(all_opts))
        return new_action(environment_id=self.environment_id)

    def remove_one(self):
        """
        Removes a random leaf from the tree.
        """
        if not self.action_root:
            return False
        action = random.choice(self)
        return self.remove_action(action)

    def mutate(self):
        """
        Mutates this action tree with respect to a given direction.
        """
        pick = random.uniform(0, 1)
        if pick < 0.20 or not self.action_root:
            new_action = self.get_rand_action(direction=self.direction)
            self.add_action(new_action)
        elif pick < 0.65 and self.action_root:
            action = random.choice(self)
            action.mutate(environment_id=self.environment_id)
        # If this individual has never been run under the evaluator,
        # or if it ran and it failed, it won't have an environment_id,
        # which means it has no saved packets to read from.
        elif pick < 0.80 and self.environment_id:
            self.trigger.mutate(self.environment_id)
        else:
            self.remove_one()
        return self

    def choose_one(self):
        """
        Picks a random element in the tree.
        """
        # If this is an empty tree, return None
        if not self.action_root:
            return None
        return random.choice(self)

    def get_parent(self, node):
        """
        Returns the parent of the given node and direction of the child.
        """
        # If we're given None, bail with None, None
        if not node:
            return None, None
        for action in self:
            if action.left == node:
                return action, "left"
            if action.right == node:
                return action, "right"
        return None, None

    def swap(self, my_donation, other_tree, other_donation):
        """
        Swaps a node in this tree with a node in another tree.
        """
        parent, direction = self.get_parent(my_donation)
        other_parent, other_direction = other_tree.get_parent(other_donation)
        # If this tree is empty or I'm trying to donate my root
        if not my_donation or not parent:
            parent = self
            direction = "action_root"
        # if the other tree is empty or they are trying to donate their root
        if not other_donation or not other_parent:
            other_parent = other_tree
            other_direction = "action_root"

        setattr(parent, direction, other_donation)
        setattr(other_parent, other_direction, my_donation)

        return True

    def mate(self, other_tree):
        """
        Mates this tree with another tree.
        """
        # If both trees are empty, nothing to do
        if not self.action_root and not other_tree.action_root:
            return False

        # Chose an action node in this tree to swap
        my_swap_node = self.choose_one()
        other_swap_node = other_tree.choose_one()

        return self.swap(my_swap_node, other_tree, other_swap_node)

    def pretty_print_help(self, root, visual=False, parent=None):
        """
        Pretty prints the tree.
         - root is the highest-level node you wish to start printing
         - [visual] controls whether a png should be created, by default, this is false.
         - [parent] is an optional parameter specifying the parent of a given node, should
           only be used by this function.

        Returns the root with its children as an anytree node.
        """
        if not root:
            return None
        if visual:
            newroot = anytree.Node(str(root) + "(" + str(root.ident) + ")", parent=parent)
        else:
            newroot = anytree.Node(str(root), parent=parent)

        if root.left:
            newroot.left = self.pretty_print_help(root.left, visual, parent=newroot)
        else:
            if not root.terminal:
                # Drop never sends packets
                newroot.left = anytree.Node(' ===> ', parent=newroot)

        if root.right:
            newroot.right = self.pretty_print_help(root.right, visual, parent=newroot)
        else:
            if (not root.terminal and root.branching):
                # Tamper only has one child
                newroot.right = anytree.Node(' ===> ', parent=newroot)

        return newroot


    def pretty_print(self, visual=False):
        """
        Pretty prints the tree.
        """
        if visual:
            newroot = self.pretty_print_help(self.action_root, visual=True)
            if newroot:
                DotExporter(newroot).to_picture("tree.png")
        else:
            newroot = self.pretty_print_help(self.action_root, visual=False)
        if not newroot:
            return ""
        # use an array and join so there's never an issue with newlines at the end
        pretty_string = []
        for pre, _fill, node in anytree.RenderTree(newroot):
            pretty_string.append(("%s%s" % (pre, node.name)))
        return "%s\n%s" % (str(self.trigger), '\n'.join(pretty_string))
