from actions.action import Action


class DuplicateAction(Action):
    """
    Defines the DuplicateAction - returns two copies of the given packet.
    """
    frequency = 3
    def __init__(self, environment_id=None):
        Action.__init__(self, "duplicate", "out")
        self.branching = True

    def run(self, packet, logger):
        """
        The duplicate action duplicates the given packet and returns one copy
        for the left branch, and one for the right branch.
        """
        logger.debug("  - Duplicating given packet %s" % str(packet))
        return packet, packet.copy()

    def mutate(self, environment_id=None):
        """
        Swaps its left and right child
        """
        self.left, self.right = self.right, self.left
