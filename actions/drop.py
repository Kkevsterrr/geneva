from actions.action import Action

class DropAction(Action):
    """
    Geneva action to drop the given packet.
    """
    frequency = 1

    def __init__(self, environment_id=None):
        """
        Initializes this drop action.

        Args:
            environment_id (str, optional): Environment ID of the strategy we are a part of
        """
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
