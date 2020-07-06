import random

import actions.utils
import actions.tree


class Strategy(object):
    def __init__(self, in_actions, out_actions, environment_id=None):
        self.in_actions = in_actions
        self.out_actions = out_actions
        self.descendents = []

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

    def initialize(self, logger, num_in_trees, num_out_trees, num_in_actions, num_out_actions, seed, disabled=None):
        """
        Initializes a new strategy object randomly.
        """
        # Disable specific forests if none requested
        if num_in_trees == 0:
            self.in_enabled = False

        if num_out_trees == 0:
            self.out_enabled = False

        # If a specific population seed is requested, build using that
        if seed:
            starting_strat = actions.utils.parse(seed, logger)
            self.out_actions = starting_strat.out_actions
            self.in_actions = starting_strat.in_actions
            return self

        self.init_from_scratch(num_in_trees, num_out_trees, num_in_actions, num_out_actions, disabled=disabled)
        return self

    def init_from_scratch(self, num_in_trees, num_out_trees, num_in_actions, num_out_actions, disabled=None):
        """
        Initializes this individual by drawing random actions.
        """
        for _ in range(0, num_in_trees):
            # Define a new in action tree
            in_tree = actions.tree.ActionTree("in")
            # Initialize the in tree
            in_tree.initialize(num_in_actions, self.environment_id, disabled=disabled)
            # Add them to this strategy
            self.in_actions.append(in_tree)

        for _ in range(0, num_out_trees):
            # Define a new out action tree
            out_tree = actions.tree.ActionTree("out")
            # Initialize the out tree
            out_tree.initialize(num_out_actions, self.environment_id, disabled=disabled)
            # Add them to this strategy
            self.out_actions.append(out_tree)


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

    def mutate_dir(self, trees, direction, logger):
        """
        Mutates a list of trees. Requires the direction the tree operates on
        (in or out).
        """
        pick = random.uniform(0, 1)
        if pick < 0.1 or not trees:
            new_tree = actions.tree.ActionTree(direction)
            new_tree.initialize(1, self.environment_id)
            trees.append(new_tree)
        elif pick < 0.2 and trees:
            trees.remove(random.choice(trees))
        elif pick < 0.25 and trees and len(trees) > 1:
            random.shuffle(trees)
        else:
            for action_tree in trees:
                action_tree.mutate()

    def mutate(self, logger):
        """
        Top level mutation function for a strategy. Simply mutates the out
        and in trees.
        """
        if self.in_enabled:
            self.mutate_dir(self.in_actions, "in", logger)
        if self.out_enabled:
            self.mutate_dir(self.out_actions, "out", logger)
        return self


def swap_one(forest1, forest2):
    """
    Swaps a random tree from forest1 and forest2.

    It picks a random element within forest1 and a random element within forest2,
    chooses a random index within each forest, and inserts the random element
    """
    assert type(forest1) == list
    assert type(forest2) == list
    rand_idx1, rand_idx2 = 0, 0
    donation, other_donation = None, None
    if forest1:
        donation = random.choice(forest1)
        forest1.remove(donation)
        if len(forest1) > 0:
            rand_idx1 = random.choice(list(range(0, len(forest1))))

    if forest2:
        other_donation = random.choice(forest2)
        forest2.remove(other_donation)
        if len(forest2) > 0:
            rand_idx2 = random.choice(list(range(0, len(forest2))))

    if other_donation:
        forest1.insert(rand_idx1, other_donation)

    if donation:
        forest2.insert(rand_idx2, donation)

    return True


def do_mate(forest1, forest2):
    """
    Performs mating between two given forests (lists of trees).
    With 80% probability, a random tree from each forest are mated,
    otherwise, a random tree is swapped between them.
    """
    # If 80% and there are trees in both forests to mate, or
    # if there is only 1 tree in each forest, mate those trees
    if (random.random() < 0.8 and forest1 and forest2) or \
       (len(forest1) == 1 and len(forest2) == 1):
        tree1 = random.choice(forest1)
        tree2 = random.choice(forest2)
        return tree1.mate(tree2)
    # Otherwise, swap a random tree from each forest
    elif forest1 or forest2:
        return swap_one(forest1, forest2)
    return False


def mate(ind1, ind2, indpb):
    """
    Executes a uniform crossover that modify in place the two
    individuals. The attributes are swapped according to the
    *indpb* probability.
    """
    out_success, in_success = True, True
    if ind1.out_enabled and random.random() < indpb:
        out_success = do_mate(ind1.out_actions, ind2.out_actions)

    if ind1.in_enabled and random.random() < indpb:
        in_success = do_mate(ind1.in_actions, ind2.in_actions)

    return out_success and in_success
