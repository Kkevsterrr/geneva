"""
Censor 3  ----> CENSOR 2

Designed to be run by the evaluator.

TCP Censor that synchronizes on first SYN only, works 100% of the time, sends 5 RSTs to
server AND client.
"""

import logging
import netifaces
import layers.packet
# Disable scapy ::1 warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, wrpcap

from censors.censor import Censor


class Censor3(Censor):
    """
    TCP Censor that synchronizes on first SYN only, works 100% of the time, sends 5 RSTs to
    server AND client.
    """
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num):
        Censor.__init__(self, environment_id, log_dir, log_level, port, queue_num)
        self.forbidden = forbidden
        self.enabled = True
        self.tcb = 0
        self.drop_all_from = None
        self.num = 0
        self.censor_interfaces = netifaces.interfaces()
        if(len(self.censor_interfaces) > 1) and 'eth0' in self.censor_interfaces:
            self.censor_ip = netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr']

    def check_censor(self, packet):
        """
        Check if the censor should run against this packet. Returns true or false.
        """
        try:
            self.num += 1

            # Only censor TCP packets for now
            self.logger.debug("Inbound packet to censor: " + layers.packet.Packet._str_packet(packet))
            if "TCP" not in packet:
                return False

            if packet["TCP"].sprintf('%TCP.flags%') == "S":
                self.tcb = packet["TCP"].seq + 1
                self.logger.debug("Synchronizing TCB on packet " + layers.packet.Packet._str_packet(packet))
                return False

            if packet["TCP"].seq == self.tcb:
                self.tcb += len(self.get_payload(packet))

            else:
                self.logger.debug("Ignoring packet: " + layers.packet.Packet._str_packet(packet))
                return False

            for keyword in self.forbidden:
                if keyword in self.get_payload(packet):
                    self.logger.debug("Packet triggered censor: " + layers.packet.Packet._str_packet(packet))
                    return True

            return False
        except Exception:
            self.logger.exception("Censor 3 Error caught.")
            return False

    def censor(self, scapy_packet):
        """
        Send 5 resets to the client and the server.
        """
        client_ip_rst = IP(src=scapy_packet[IP].dst, dst=scapy_packet[IP].src)
        client_tcp_rst = TCP(
            dport=scapy_packet[TCP].sport,
            sport=scapy_packet[TCP].dport,
            ack=scapy_packet[TCP].seq+len(str(scapy_packet[TCP].payload)),
            seq=scapy_packet[TCP].ack,
            flags="R"
        )
        client_rst = client_ip_rst / client_tcp_rst

        server_ip_rst = IP(src=self.censor_ip, dst=scapy_packet[IP].dst)
        server_tcp_rst = TCP(
            dport=scapy_packet[TCP].dport,
            sport=scapy_packet[TCP].sport,
            ack=scapy_packet[TCP].ack,
            seq=scapy_packet[TCP].seq,
            flags="R"
        )
        server_tcp_rst.show()
        server_rst = server_ip_rst / server_tcp_rst

        for _ in range(0, 5):
            self.mysend(client_rst)
            self.mysend(server_rst)
