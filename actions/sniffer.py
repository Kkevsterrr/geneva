import threading
import os

import layers.packet
from scapy.all import sniff
from scapy.utils import PcapWriter


class Sniffer():
    """
    The sniffer class lets the user begin and end sniffing whenever in a given location with a port to filter on.
    Call start_sniffing to begin sniffing and stop_sniffing to stop sniffing.
    """

    def __init__(self, location, port, logger):
        """
        Intializes a sniffer object.
        Needs a location and a port to filter on.
        """
        self.stop_sniffing_flag = False
        self.location = location
        self.port = port
        self.pcap_thread = None
        self.packet_dumper = None
        self.logger = logger
        full_path = os.path.dirname(location)
        assert port, "Need to specify a port in order to launch a sniffer"
        if not os.path.exists(full_path):
            os.makedirs(full_path)

    def __packet_callback(self, scapy_packet):
        """
        This callback is called whenever a packet is applied.
        Returns true if it should finish, otherwise, returns false.
        """
        packet = layers.packet.Packet(scapy_packet)
        for proto in ["TCP", "UDP"]:
            if(packet.haslayer(proto) and ((packet[proto].sport == self.port) or (packet[proto].dport == self.port))):
                break
        else:
            return self.stop_sniffing_flag

        self.logger.debug(str(packet))
        self.packet_dumper.write(scapy_packet)
        return self.stop_sniffing_flag

    def __spawn_sniffer(self):
        """
        Saves pcaps to a file. Should be run as a thread.
        Ends when the stop_sniffing_flag is set. Should not be called by user
        """
        self.packet_dumper = PcapWriter(self.location, append=True, sync=True)
        while(self.stop_sniffing_flag == False):
            sniff(stop_filter=self.__packet_callback, timeout=1)

    def start_sniffing(self):
        """
        Starts sniffing. Should be called by user.
        """
        self.stop_sniffing_flag = False
        self.pcap_thread = threading.Thread(target=self.__spawn_sniffer)
        self.pcap_thread.start()
        self.logger.debug("Sniffer starting to port %d" % self.port)

    def __enter__(self):
        """
        Defines a context manager for this sniffer; simply starts sniffing.
        """
        self.start_sniffing()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """
        Defines exit context manager behavior for this sniffer; simply stops sniffing.
        """
        self.stop_sniffing()

    def stop_sniffing(self):
        """
        Stops the sniffer by setting the flag and calling join
        """
        if(self.pcap_thread):
            self.stop_sniffing_flag = True
            self.pcap_thread.join()
        self.logger.debug("Sniffer stopping")
