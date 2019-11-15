from actions.action import Action

class DropAction(Action):
    def __init__(self, environment_id=None):
        Action.__init__(self, "drop", "both")
        self.terminal = True
        self.branching = False

    def run(self, packet, logger):
        """
        The drop action returns None for both it's left and right children, and
        does not pass the packet along for continued use.
        """
        logger.debug("  - Dropping given packet.")
        return None, None
