import random
from actions.action import Action
import layers.packet

from scapy.all import IP, TCP, fragment


MAX_UINT = 4294967295


class FragmentAction(Action):
    """
    Defines the FragmentAction for Geneva - fragments or segments the given packet.
    """
    frequency = 2
    def __init__(self, environment_id=None, correct_order=None, fragsize=-1, segment=True, overlap=0):
        """
        Initializes a fragment action object.

        Args:
            environment_id (str, optional): Environment ID of the strategy this object is a part of
            correct_order (bool, optional): Whether or not the fragments/segments should be returned in the correct order
            fragsize (int, optional): The index this packet should be cut. Defaults to -1, which cuts it in half.
            segment (bool, optional): Whether we should perform fragmentation or segmentation
            overlap (int, optional): How many bytes the fragments/segments should overlap
        """
        Action.__init__(self, "fragment", "out")
        self.enabled = True
        self.branching = True
        self.terminal = False
        self.fragsize = fragsize
        self.segment = segment
        self.overlap = overlap
        if correct_order == None:
            self.correct_order = self.get_rand_order()
        else:
            self.correct_order = correct_order

    def get_rand_order(self):
        """
        Randomly decides if the fragments should be reversed.
        """
        return random.choice([True, False])

    def fragment(self, original, fragsize):
        """
        Fragments a packet into two, given the size of the first packet (0:fragsize)
        Always returns two packets
        """
        if fragsize == 0:
            frags = [original]
        else:
            frags = fragment(original, fragsize=fragsize)
        # If there were more than 2 fragments, join the loads so we still have 2 packets
        if len(frags) > 2:
            for frag in frags[2:]:
                frags[1]["IP"].load += frag["IP"].load
            # After scapy fragmentation, the flags field is set to "MF+DF"
            # In order for the packet to remain valid, strip out the "MF"
            frags[1]["IP"].flags = "DF"
        # If scapy tried to fragment but there were only enough bytes for 1 packet, just duplicate it
        elif len(frags) == 1:
            frags.append(frags[0].copy())

        return frags[0], frags[1]

    def ip_fragment(self, packet, logger):
        """
        Perform IP fragmentation.
        """
        if not packet.haslayer("IP") or not hasattr(packet["IP"], "load"):
            return packet, packet.copy() # duplicate if no TCP or no payload to segment
        load = ""
        if packet.haslayer("TCP"):
            load = bytes(packet["TCP"])
        elif packet.haslayer("UDP"):
            load = bytes(packet["UDP"])
        else:
            load = bytes(packet["IP"].load)

        # If there is no load, duplicate the packet
        if not load:
            return packet, packet.copy()

        if self.fragsize == -1 or (self.fragsize * 8) > len(load) or len(load) <= 8:
            fragsize = int(int(((int(len(load)/2))/8))*8)
            frags = self.fragment(packet.copy().packet, fragsize=fragsize)
        else:
            # packet can be fragmented as requested
            frags = self.fragment(packet.copy().packet, fragsize=self.fragsize*8)
        packet1 = layers.packet.Packet(frags[0])
        packet2 = layers.packet.Packet(frags[1])
        if self.correct_order:
            return packet1, packet2
        else:
            return packet2, packet1

    def tcp_segment(self, packet, logger):
        """
        Segments a packet into two, given the size of the first packet (0:fragsize)
        Always returns two packets, since fragment is a branching action, so if we
        are unable to segment, it will duplicate the packet.

        If overlap is specified, it will select n bytes from the second packet
        and append them to the first, and increment the sequence number accordingly
        """
        if not packet.haslayer("TCP") or not hasattr(packet["TCP"], "load") or not packet["TCP"].load:
            return packet, packet.copy() # duplicate if no TCP or no payload to segment

        # Get the original payload and delete it from the packet so it
        # doesn't come along when copying the TCP layer
        payload = packet["TCP"].load
        del(packet["TCP"].load)

        fragsize = self.fragsize
        if self.fragsize == -1 or self.fragsize > len(payload) - 1:
            fragsize = int(len(payload)/2)

        # Craft new packets

        # Make sure we don't go out of bounds by choosing the min
        overlap_bytes = min(len(payload[fragsize:]), self.overlap)
        # Attach these bytes to the first packet
        pkt1 = IP(packet["IP"])/payload[:fragsize + overlap_bytes]
        pkt2 = IP(packet["IP"])/payload[fragsize:]

        # We cannot rely on scapy's native parsing here - if a previous action has changed the
        # fragment offset, scapy will not identify this as TCP, so we must do it for scapy
        if not pkt1.haslayer("TCP"):
            pkt1 = IP(packet["IP"])/TCP(bytes(pkt1["IP"].load))

        if not pkt2.haslayer("TCP"):
            pkt2 = IP(packet["IP"])/TCP(bytes(pkt2["IP"].load))

        packet1 = layers.packet.Packet(pkt1)
        packet2 = layers.packet.Packet(pkt2)

        # Reset packet2's SYN number
        if packet2["TCP"].seq + fragsize > MAX_UINT:
            # Wrap sequence numbers around if greater than MAX_UINT
            packet2["TCP"].seq = packet2["TCP"].seq + fragsize - MAX_UINT - 1
        else:
            packet2["TCP"].seq += fragsize

        del packet1["IP"].chksum
        del packet2["IP"].chksum
        del packet1["IP"].len
        del packet2["IP"].len
        del packet1["TCP"].chksum
        del packet2["TCP"].chksum
        del packet1["TCP"].dataofs
        del packet2["TCP"].dataofs

        if self.correct_order:
            return [packet1, packet2]
        else:
            return [packet2, packet1]

    def run(self, packet, logger):
        """
        The fragment action fragments each given packet.
        """
        logger.debug("  - Fragmenting given packet %s" % str(packet))
        if self.segment:
            return self.tcp_segment(packet, logger)
        else:
            return self.ip_fragment(packet, logger)

    def __str__(self):
        """
        Returns a string representation with the fragsize
        """
        s = Action.__str__(self)
        if not self.overlap:
            ending = "}"
        else:
            ending = ":" + str(self.overlap) + "}"
        if self.segment:
            s += "{" + "tcp" + ":" + str(self.fragsize)  + ":" + str(self.correct_order) + ending
        else:
            s += "{" + "ip" + ":"+ str(self.fragsize)  + ":" + str(self.correct_order) + ending
        return s

    def parse(self, string, logger):
        """
        Parses a string representation of fragmentation. Nothing particularly special,
        but it does check for a the fragsize.

        Note that the given logger is a DIFFERENT logger than the logger passed
        to the other functions, and they cannot be used interchangeably. This logger
        is attached to the main GA driver, and is run outside the evaluator. When the
        action is actually run, it's run within the evaluator, which by necessity must
        pass in a different logger.
        """

        # Count the number of params in this given string
        num_parameters = string.count(":")

        # If num_parameters is greater than 2, it's not a valid fragment action
        if num_parameters == 2:
            params = string.split(":")
            seg, fragsize, correct_order = params
            overlap = 0
            if "tcp" in seg:
                self.segment = True
            else:
                self.segment = False

        elif num_parameters == 3:
            params = string.split(":")
            seg, fragsize, correct_order, overlap = params
            if overlap.endswith("}"):
                overlap = overlap[:-1] # Chop off trailing }
            if "tcp" in seg:
                self.segment = True
            else:
                self.segment = False

        else:
            msg = "Cannot parse fragment action %s" % string
            logger.error(msg)
            raise Exception(msg)

        try:
            # Try to convert to int
            self.fragsize = int(fragsize)
            self.overlap = int(overlap)
        except ValueError as e:
            print(e)
            msg = "Cannot parse fragment action %s" % string
            logger.error(msg)
            raise Exception(msg)

        # Parse ordering
        if correct_order.startswith('True'):
            self.correct_order = True
        else:
            self.correct_order = False

        return True

    def mutate(self, environment_id=None):
        """
        Mutates the fragment action - it either chooses a new segment offset,
        switches the packet order, and/or changes whether it segments or fragments.
        """
        self.correct_order = self.get_rand_order()
        self.segment = random.choice([True, True, True, False])
        if self.segment:
            if random.random() < 0.5:
                self.fragsize = int(random.uniform(1, 60))
            else:
                self.fragsize = -1
        else:
            if random.random() < 0.2:
                self.fragsize = int(random.uniform(1, 50))
            else:
                self.fragsize = -1

        if random.random() < .5:
            # Somewhat aggressively overlap
            if random.random() < .5:
                if self.fragsize == -1:
                    self.overlap = 5
                else:
                    self.overlap = int(self.fragsize/2)
            else:
                self.overlap = int(random.uniform(1, 50))

        return self
