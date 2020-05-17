"""
Dummy

Designed to be run by the evaluator.

Censors nothing - dummy censor for infrastructure testing.  
"""

from censors.censor import Censor


class Dummy(Censor):
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num):
        Censor.__init__(self, environment_id, log_dir, log_level, port, queue_num)

    def check_censor(self, packet):
        """
        Check if the censor should run against this packet. Returns False for dummy censor.
        """
        return False

    def censor(self, scapy_packet):
        """
        Does nothing.
        """
        return False
