from layers.layer import Layer
from scapy.all import UDP

class UDPLayer(Layer):
    """
    Defines an interface to access UDP header fields.
    """
    name = "UDP"
    protocol = UDP
    _fields = [
        "sport",
        "dport",
        "chksum",
        "len",
        "load"
    ]
    fields = _fields

    def __init__(self, layer):
        """
        Initializes the UDP layer.
        """
        Layer.__init__(self, layer)
        self.getters = {
            'load' : self.get_load,
        }
        self.setters = {
            'load' : self.set_load,
        }
        self.generators = {
            'load' : self.gen_load,
        }