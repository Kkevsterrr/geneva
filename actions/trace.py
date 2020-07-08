import socket
import time

from scapy.config import conf

from actions.action import Action
import actions.utils


class TraceAction(Action):
    """
    The Trace Action is used to TTL probe/traceroute a censor. When the action fires,
    it sends the captured packet with increasing ttls within a certain range

    TraceAction is an experimental action that is never used
    in actual evolution
    """
    # Do not select Trace during evolutions
    frequency = 0
    def __init__(self, start_ttl=1, end_ttl=64, environment_id=None):
        """
        Initializes the trace action.

        Args:
            start_ttl (int): Starting TTL to use
            end_ttl (int): TTL to end with
            environment_id (str, optional): Environment ID associated with the strategy we are a part of
        """
        Action.__init__(self, "trace", "out")
        self.enabled = True
        self.terminal = True
        self.branching = False
        self.start_ttl = start_ttl
        self.end_ttl = end_ttl
        # Since running this action might take enough time that additional packets
        # get generated, only allow this action to run once
        self.ran = False
        # Define a socket
        self.socket = conf.L3socket(iface=actions.utils.get_interface())

    def run(self, packet, logger):
        """
        The trace action sends the captured packet repeatedly with increasing ttl probes
        defined between the range of start_ttl to end_ttl. This is an experimental action,
        and is not used for training.
        """
        logger.debug("  - Starting Trace action")

        if not packet.haslayer("IP"):
            logger.debug("  - Could not identify IP header to perform ttl trace")
            return packet, None

        if self.ran:
            logger.debug("  - trace action already ran. Dropping given traffic.")
            return None, None

        self.ran = True
        for ttl in range(self.start_ttl, self.end_ttl):
            logger.debug("  - ttl=%d" % ttl)
            packet.set("IP", "ttl", ttl)
            logger.debug("Sending packet %s", str(packet))
            self.socket.send(packet.packet)
            time.sleep(1)

        return None, None

    def __str__(self):
        """
        Returns a string representation.
        """
        s = Action.__str__(self)
        s += "{%d:%d}" % (self.start_ttl, self.end_ttl)
        return s

    def parse(self, string, logger):
        """
        Parses a string representation for this object.
        """
        if not string:
            return False
        try:
            self.start_ttl, self.end_ttl = string.split(":")
            self.start_ttl = int(self.start_ttl)
            self.end_ttl = int(self.end_ttl)
            if self.start_ttl > self.end_ttl:
                logger.error("Cannot use a trace with a start ttl greater than end_ttl (%d > %d)" % (self.start_ttl, self.end_ttl))
                return False
        except ValueError:
            logger.exception("Cannot parse ttls from given data %s" % string)
            return False

        return True
