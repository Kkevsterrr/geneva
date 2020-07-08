"""
Censor 4

Dropping censor that synchronizes TCB on all SYN and ACK packets.
"""

import layers.packet
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP

from censors.censor import Censor


class Censor4(Censor):
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num):
        Censor.__init__(self, environment_id, log_dir, log_level, port, queue_num)
        self.forbidden = forbidden
        self.tcb = 0
        self.drop_all_from = None
        self.num = 0

    def check_censor(self, packet, verbose=False):
        """
        Check if the censor should run against this packet. Returns true or false.
        """
        try:
            self.num += 1


            self.logger.debug("Inbound packet to censor: " + layers.packet.Packet._str_packet(packet))
            if self.drop_all_from == packet["IP"].src:
                self.logger.debug("Dropping all from this IP %s..." % self.drop_all_from)
                return True

            # Only censor TCP packets for now
            if "TCP" not in packet:
                return False

            # Initial TCP synchronization
            if "S" == packet["TCP"].sprintf('%TCP.flags%'):
                self.tcb = packet["TCP"].seq + 1
                self.logger.debug(("Synchronizing TCB (%d) on S packet " + layers.packet.Packet._str_packet(packet)) % self.tcb)
                return False

            if "A" == packet["TCP"].sprintf('%TCP.flags%'):
                self.tcb = packet["TCP"].seq
                self.logger.debug(("Synchronizing TCB (%d) on A packet " + layers.packet.Packet._str_packet(packet)) % self.tcb)
                return False

            # If we're tracking this packet stream
            if packet["TCP"].seq == self.tcb:
                self.tcb += len(self.get_payload(packet))
            else:
                self.logger.debug("Ignoring packet: " + layers.packet.Packet._str_packet(packet))
                return False

            # Check if any forbidden words appear in the packet payload
            for keyword in self.forbidden:
                if keyword in self.get_payload(packet):
                    self.logger.debug("Packet triggered censor: " + layers.packet.Packet._str_packet(packet))
                    return True

            return False
        except Exception:
            self.logger.exception("Exception caught by censor 4")
            return False

    def censor(self, scapy_packet):
        """
        Marks this IP to be dropped in the future and drops this packet.
        """
        self.drop_all_from = scapy_packet["IP"].src
        self.logger.debug("Marking IP %s for dropping..." % self.drop_all_from)
        return "drop"











