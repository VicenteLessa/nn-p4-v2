from scapy.all import *

WORDSIZE 32
SLACK 8

class ANN(Packet):
    fields_desc = [
        BitField("neuron_id", 0, 32),
        BitField("data", 0, WORDSIZE),
        BitField("run_id", 0, 16),
        BitField("slack", 0, SLACK)        
    ]

    def __repr__(self):
        return (self.neuron_id, self.data, self.run_id)



    
    
bind_layers(Ether,ann,type=0x88B5)