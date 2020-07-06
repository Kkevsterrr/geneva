"""
Censor 7 is a IP dropping TCB Teardown censor. It only tears down a TCB
if the full tuple of the TCB matches (src, dst, sport, dport).
Does not check if the SEQ/ACK are in window for the FIN/RST.
"""

import logging
import layers.packet
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP

from censors.censor import Censor


class Censor7(Censor):
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num):
        Censor.__init__(self, environment_id, log_dir, log_level, port, queue_num)
        self.forbidden = forbidden
        self.tcb = {}
        self.drop_all_from = None

    def check_censor(self, packet, verbose=False):
        """
        Check if the censor should run against this packet. Returns true or false.
        """
        try:
            self.logger.debug("Inbound packet to censor: " + layers.packet.Packet._str_packet(packet))
            if self.drop_all_from == packet["IP"].src:
                self.logger.debug("Dropping all from this IP %s..." % self.drop_all_from)
                return True

            # Only censor TCP packets for now
            if "TCP" not in packet:
                return False

            # Clients can close connections with any of these flags
            if packet["TCP"].sprintf('%TCP.flags%') in ["R", "RA", "F"]:
                # If a TCB has already been setup, check that this packet matches it
                if self.tcb and \
                   packet["IP"].src in self.tcb["ips"] and \
                   packet["IP"].dst in self.tcb["ips"] and \
                   packet["TCP"].dport in self.tcb["ports"] and \
                   packet["TCP"].sport in self.tcb["ports"]:

                    self.tcb = None
                    self.logger.debug(("Tearing down TCB on packet " + layers.packet.Packet._str_packet(packet)))
                    return False

            elif not self.tcb and self.tcb is not None:
                self.tcb["ips"] = [packet["IP"].src, packet["IP"].dst]
                self.tcb["ports"] = [packet["TCP"].sport, packet["TCP"].dport]

            if self.tcb is None:
                self.logger.debug("Ignoring packet: " + layers.packet.Packet._str_packet(packet))
                return False

            # Check if any forbidden words appear in the packet payload
            for keyword in self.forbidden:
                if keyword in self.get_payload(packet):
                    self.logger.debug("Packet triggered censor: " + layers.packet.Packet._str_packet(packet))
                    return True

            return False
        except Exception:
            self.logger.exception("Exception caught by Censor 7")
            return False

    def censor(self, scapy_packet):
        """
        Marks this IP to be dropped in the future and drops this packet.
        """
        self.drop_all_from = scapy_packet["IP"].src
        self.logger.debug("Marking IP %s for dropping..." % self.drop_all_from)
        return "drop"
