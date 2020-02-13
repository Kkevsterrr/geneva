from actions.action import Action

class SleepAction(Action):
    def __init__(self, time=1, environment_id=None):
        Action.__init__(self, "sleep", "both")
        self.terminal = False
        self.branching = False
        self.time = time

    def run(self, packet, logger):
        """
        The sleep action simply passes along the packet it was given with an instruction for how long the engine should sleep before sending it.
        """
        logger.debug("  - Adding %g sleep to given packet." % self.time)
        packet.sleep = self.time
        return packet, None

    def __str__(self):
        """
        Returns a string representation.
        """
        s = Action.__str__(self)
        s += "{%g}" % self.time
        return s

    def parse(self, string, logger):
        """
        Parses a string representation for this object.
        """
        try:
            if string:
                self.time = float(string)
        except ValueError:
            logger.exception("Cannot parse time %s" % string)
            return False

        return True
