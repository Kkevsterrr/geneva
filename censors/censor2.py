"""
Censor 2  ----> CENSOR 1

Designed to be run by the evaluator.

TCP Censor that synchronizes on first SYN only, works 100% of the time, sends 5 RSTs to client.
"""

import layers.packet
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP

from censors.censor import Censor


class Censor2(Censor):
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num):
        Censor.__init__(self, environment_id, log_dir, log_level, port, queue_num)
        self.forbidden = forbidden
        self.tcb = 0
        self.drop_all_from = None

    def check_censor(self, packet):
        """
        Check if the censor should run against this packet. Returns true or false.
        """
        try:
            self.logger.debug("Inbound packet to censor: %s", layers.packet.Packet._str_packet(packet))

            # Only censor TCP packets for now
            if "TCP" not in packet:
                return False

            if packet["TCP"].sprintf('%TCP.flags%') == "S":
                self.tcb = packet["TCP"].seq + 1
                self.logger.debug("Synchronizing TCB on packet: %s", layers.packet.Packet._str_packet(packet))
                return False

            if packet["TCP"].seq == self.tcb:
                self.tcb += len(self.get_payload(packet))

            else:
                self.logger.debug("Ignoring packet: %s", layers.packet.Packet._str_packet(packet))
                return False

            for keyword in self.forbidden:
                if keyword in self.get_payload(packet):
                    self.logger.debug("Packet triggered censor: %s", layers.packet.Packet._str_packet(packet))
                    return True

            return False
        except Exception:
            self.logger.exception("Censor 2 exception caught.")
            return False

    def censor(self, scapy_packet):
        """
        Send 5 resets to the client.
        """
        rst = IP(src=scapy_packet[IP].dst, dst=scapy_packet[IP].src)/TCP(dport=scapy_packet[TCP].sport, sport=scapy_packet[TCP].dport, ack=scapy_packet[TCP].seq+len(str(scapy_packet[TCP].payload)), seq=scapy_packet[TCP].ack, flags="R")
        for i in range(0, 5):
            self.mysend(rst)
