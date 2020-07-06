"""
Censor 8b is a RST censor designed to mimic TCB teardown GFW behavior. It
tracks multiple connections using TCBs, but does not enter a TCB resynchronization
state if a RST or FIN, it simply tears down. It creates new TCBs for connections it is not
yet aware of, but does not check the checksums of incoming packets.
"""

import layers.packet
import netifaces
from censors.censor import Censor
from scapy.all import IP, TCP


class Censor8b(Censor):
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num):
        Censor.__init__(self, environment_id, log_dir, log_level, port, queue_num)
        self.forbidden = forbidden
        self.tcbs = []
        self.flagged_ips = []
        self.censor_interfaces = netifaces.interfaces()
        if(len(self.censor_interfaces) > 1) and 'eth0' in self.censor_interfaces:
            self.censor_ip = netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr']


    def check_censor(self, packet):
        """
        Check if the censor should run against this packet.
        Returns true or false.
        """
        try:
            self.logger.debug("Inbound packet to censor: %s" % layers.packet.Packet._str_packet(packet))
            if packet["IP"].src in self.flagged_ips:
                self.logger.debug("Content from a flagged IP detected %s..." % packet["IP"].src)
                return True

            # Only censor TCP packets for now
            if "TCP" not in packet:
                return False

            # Throw away packets that have an invalid dataofs
            if packet["TCP"].dataofs < 5:
                return False

            # If we are in a resynchronization state, or we do not yet have a connection and a new one
            # is being created, add or update a TCB
            tcb = self.get_matching_tcb(packet)
            if (not tcb and packet["TCP"].sprintf('%TCP.flags%') in ["S"]):
                # Check if we've been tracking a connection for this ip:port <-> ip:port already,
                # so we can just replace that tcb with updated info
                tcb = self.get_partial_tcb(packet)
                if tcb is None:
                    self.logger.debug("Making a new TCB for packet %s" % layers.packet.Packet._str_packet(packet))
                    tcb = {}

                    tcb["src"] = packet["IP"].src
                    tcb["dst"] = packet["IP"].dst
                    tcb["sport"] = packet["TCP"].sport
                    tcb["dport"] = packet["TCP"].dport
                    tcb["seq"] = packet["TCP"].seq
                # If we're synchronizing on a SYN flag, need to add 1.
                if packet["TCP"].sprintf('%TCP.flags%') in ["S"]:
                    tcb["seq"] += 1
                else:
                    tcb["seq"] += len(self.get_payload(packet))

                self.tcbs.append(tcb)
                self.logger.debug("Synchronizing a TCB (%s) on packet %s " % (str(tcb), layers.packet.Packet._str_packet(packet)))
                return False
            # If connection is getting torn down
            elif tcb and packet["TCP"].sprintf('%TCP.flags%') in ["R", "RA"]:
                self.tcbs.remove(tcb)
                self.logger.debug(("Deleting TCB for packet %s" % layers.packet.Packet._str_packet(packet)))
                return False

            if not tcb:
                self.logger.debug("No TCB matches packet.")
                return False

            # Keep the TCB up to date
            tcb["seq"] += len(self.get_payload(packet))

            # Check if any forbidden words appear in the packet payload
            for keyword in self.forbidden:
                if keyword in self.get_payload(packet):
                    self.logger.debug("Packet triggered censor: %s" % layers.packet.Packet._str_packet(packet))
                    return True

            return False
        except Exception:
            self.logger.exception("Exception caught by Censor 8b")
            return False

    def censor(self, scapy_packet):
        """
        Adds client and server IPs to flagged IP list.
        """
        if scapy_packet["IP"].src not in self.flagged_ips:
            self.flagged_ips.append(scapy_packet["IP"].src)
            self.logger.debug("Marking IP %s for dropping..." % scapy_packet["IP"].src)
        if scapy_packet["IP"].dst not in self.flagged_ips:
            self.flagged_ips.append(scapy_packet["IP"].dst)
            self.logger.debug("Marking IP %s for dropping..." % scapy_packet["IP"].dst)

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

        return "accept"

    def get_matching_tcb(self, packet):
        """
        Checks if the packet matches the stored TCB.
        """
        for tcb in self.tcbs:
            self.logger.debug("Checking %s against packet %s" % (str(tcb), layers.packet.Packet._str_packet(packet)))

            if (packet["IP"].src == tcb["src"] and \
                packet["IP"].dst == tcb["dst"] and \
                packet["TCP"].sport == tcb["sport"] and \
                packet["TCP"].dport == tcb["dport"] and \
                packet["TCP"].seq == tcb["seq"]):
                return tcb
        return None

    def get_partial_tcb(self, packet):
        """
        Checks if the packet matches an existing connection, regardless if the SEQ/ACK
        are correct.
        """
        for tcb in self.tcbs:
            self.logger.debug("Checking %s against packet %s for partial match" % (str(tcb), layers.packet.Packet._str_packet(packet)))

            if (packet["IP"].src == tcb["src"] and \
                packet["IP"].dst == tcb["dst"] and \
                packet["TCP"].sport == tcb["sport"] and \
                packet["TCP"].dport == tcb["dport"]):
                return tcb
        return None
