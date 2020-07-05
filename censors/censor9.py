"""
Censor 9 is a IP dropping TCB Teardown censor. It does not tear down its TCB,
but it will resynchronize it's TCB if a RST or FIN is sent if the full tuple
of the TCB matches (src, dst, sport, dport, seq).

More closely mimics GFW behavior.
"""

import logging
import layers.packet
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP

from censors.censor import Censor


class Censor9(Censor):
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num):
        Censor.__init__(self, environment_id, log_dir, log_level, port, queue_num)
        self.forbidden = forbidden
        self.tcb = {}
        self.drop_all_from = None
        self.resynchronize = False

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

            # If we are in a resynchronization state, or we do not yet have a connection and a new one
            # is being created, definte the TCB
            if self.resynchronize or (not self.tcb and packet["TCP"].sprintf('%TCP.flags%') == "S"):
                self.tcb["src"] = packet["IP"].src
                self.tcb["dst"] = packet["IP"].dst
                self.tcb["sport"] = packet["TCP"].sport
                self.tcb["dport"] = packet["TCP"].dport
                self.tcb["seq"] = packet["TCP"].seq
                # If we're synchronizing on a SYN flag, need to add 1.
                if packet["TCP"].sprintf('%TCP.flags%') == "S":
                    self.tcb["seq"] += 1
                else:
                    self.tcb["seq"] += len(self.get_payload(packet))

                self.resynchronize = False
                self.logger.debug("Synchronizing TCB on packet " + layers.packet.Packet._str_packet(packet))
                return self.check_forbidden(packet)

            # If connection is getting torn down
            elif self.tcb_matches(packet) and \
                 (packet["TCP"].sprintf('%TCP.flags%') == "R" or \
                  packet["TCP"].sprintf('%TCP.flags%') == "F"):
                self.resynchronize = True
                self.logger.debug(("Entering resynchronization state on packet " + layers.packet.Packet._str_packet(packet)))

            if not self.tcb_matches(packet):
                self.logger.debug("TCB does not match packet.")
                return False
            # Keep the TCB up to date
            elif "seq" in self.tcb:
                self.tcb["seq"] += len(self.get_payload(packet))

            return self.check_forbidden(packet)

        except Exception:
            self.logger.exception("Exception caught by Censor 9")
            return False

    def censor(self, scapy_packet):
        """
        Marks this IP to be dropped in the future and drops this packet.
        """
        self.drop_all_from = scapy_packet["IP"].src
        self.logger.debug("Marking IP %s for dropping..." % self.drop_all_from)
        return "drop"

    def check_forbidden(self, packet):
        """
        Checks if a packet contains forbidden words.
        """
        # Check if any forbidden words appear in the packet payload
        for keyword in self.forbidden:
            if keyword in self.get_payload(packet):
                self.logger.debug("Packet triggered censor: " + layers.packet.Packet._str_packet(packet))
                return True
        return False

    def tcb_matches(self, packet):
        """
        Checks if the packet matches the stored TCB.
        """
        self.logger.debug(self.tcb)
        return not self.tcb or (self.tcb and \
               packet["IP"].src == self.tcb["src"] and \
               packet["IP"].dst == self.tcb["dst"] and \
               packet["TCP"].sport == self.tcb["sport"] and \
               packet["TCP"].dport == self.tcb["dport"] and \
               packet["TCP"].seq == self.tcb["seq"])
