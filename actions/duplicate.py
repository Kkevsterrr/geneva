from actions.action import Action


class DuplicateAction(Action):
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
