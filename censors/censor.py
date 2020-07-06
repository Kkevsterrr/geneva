import socket
socket.setdefaulttimeout(1)
import logging
import random
import os

import layers.packet
import actions.utils

# Squelch annoying scapy ::1 runtime errors
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Netfilterqueue may not work outside the docker container,
# but this file can still be imported outside the docker container
try:
    from netfilterqueue import NetfilterQueue
except ImportError:
    pass

from scapy.all import send, IP

# Note that censor.py lives in censors, so we need an extra dirname() call to get
# to the project root
BASEPATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Censor(object):
    def __init__(self, eid, log_dir, log_level, port, queue_num):
        """
        Setup censor attributes and logging.
        """
        self.enabled = True
        self.nfqueue = None
        self.running_nfqueue = False
        self.queue_num = queue_num
        self.port = port
        self.eid = eid
        self.logger = None
        self.log_dir = log_dir
        if log_level:
            self.logger = actions.utils.get_logger(BASEPATH, log_dir, __name__, "censor", eid, log_level=log_level)
            self.logger.debug("Censor created to port %d on queue %d" % (port, queue_num))

    def start(self):
        """
        Initialize the censor.
        """
        self.logger.debug("Censor initializing.")

        # Set up iptables rules to catch packets
        os.system("iptables -A FORWARD -j NFQUEUE -p tcp --sport %s --queue-num %s" % (self.port, self.queue_num))
        os.system("iptables -A FORWARD -j NFQUEUE -p tcp --dport %s --queue-num %s" % (self.port, self.queue_num))
        self.logger.debug("Censor iptables added")

        #self.running_nfqueue = True
        self.num = 0
        try:
            self.nfqueue = NetfilterQueue()
            self.logger.debug("Censor binding")
            self.nfqueue.bind(int(self.queue_num), self.callback)
            self.logger.debug("Censor bound")
            self.nfqueue.run()
        except KeyboardInterrupt:
            self.logger.debug("CENSOR GOT SHUTDOWN")
            self.shutdown()
        #self.nfqueue_socket = socket.fromfd(self.nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        #self.nfqueue_thread = threading.Thread(target=self.run_nfqueue)
        #self.nfqueue_thread.start()
        # Spin wait the main thread while running nfqueue in the other threads
        #while self.running_nfqueue:
        #    time.sleep(1)

    def check_exit(self):
        """
        Check if a shutdown flag has been written.
        """
        flag_folder = os.path.join(BASEPATH, self.log_dir, actions.utils.FLAGFOLDER)
        if not os.path.exists(flag_folder):
            os.makedirs(flag_folder)
        return os.path.exists(os.path.join(flag_folder, "shutdown"))

    def run_nfqueue(self):
        """
        Run nfqueue in a non-blocking way. Note that nfqueue reports
        that it supports non-blocking operation, but this is broken in the
        library, and the following is the workaround.
        """
        try:
            while self.running_nfqueue:
                try:
                    self.nfqueue.run_socket(self.nfqueue_socket)
                except socket.timeout:
                    self.logger.debug("Exiting")
                    # Check if we need to exit
                    if self.check_exit():
                        break
                    pass
            self.shutdown()
        except Exception:
            self.logger.exception("Exception out of run_nfqueue()")

    def mysend(self, packet):
        """
        Sends a packet with scapy.
        """
        if "TCP" in packet:
            self.logger.debug(layers.packet.Packet._str_packet(packet))
        send(packet, verbose=False)
        return

    def get_payload(self, packet):
        """
        Parse paylaod out of the given scapy packet.
        """
        payload = bytes(packet["TCP"].payload)
        if str(payload) != "b''":
            return payload
        else:
            return b""

    def shutdown(self):
        """
        Shuts down and cleans up the censor.
        """
        self.logger.debug("Shutting down censor.")
        self.running_nfqueue = False
        self.nfqueue.unbind()
        #self.nfqueue_socket.close()
        os.system("iptables -D FORWARD -j NFQUEUE -p tcp --sport %s --queue-num %s" % (self.port, self.queue_num))
        os.system("iptables -D FORWARD -j NFQUEUE -p tcp --dport %s --queue-num %s" % (self.port, self.queue_num))

    def callback(self, packet):
        """
        NFQueue bound callback to capture packets and check whether we
        want to censor it.
        """
        try:
            scapy_packet = IP(packet.get_payload())
            # Check for control check packet from evaluator to announce readiness
            if scapy_packet.sport == 2222 and scapy_packet.seq == 13337:
                # This line cannot be removed - it is to signal to the client the censor is ready
                flag_folder = os.path.join(BASEPATH, self.log_dir, actions.utils.FLAGFOLDER)
                if not os.path.exists(flag_folder):
                    os.makedirs(flag_folder)
                ready_path = os.path.join(flag_folder, "%s.censor_ready" % self.eid)
                self.logger.debug("Writing ready file to %s" % ready_path)
                if not os.path.exists(ready_path):
                    os.system("touch %s" % ready_path)
                self.logger.debug("Censor ready.")
                packet.drop()
                return
            action = "accept"
            # Check if the packet should be censored
            if self.check_censor(scapy_packet):
               # If so, trigger the censoring itself (drop packet, send RST, etc)
               action = self.censor(scapy_packet)

            if action == "drop":
                packet.drop()
            else:
                packet.accept()
        except Exception:
            self.logger.exception("Censor exception in nfqueue callback.")
