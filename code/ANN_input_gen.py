#!/usr/bin/env python
import sys
import time
from ANN_hdrs import *

def main():
    e="S"


# Classificação correta: classe 1, WEB. pacotes exemplos: (190, 338),
# Classificação errada: classe 8, era pra ser classe 1. pacotes exemplos: (190, 0),(191, 72)
# Classificação errada: classe 1, era pra ser classe 5. pacotes exemplos: (189, 150)

    attr1_pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr('eth0')) / \
                ann(neuron_id = 0, data = 190)

    attr2_pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr('h1-eth1')) / \
                ann(neuron_id = 0, data = 0)

    while (e.upper() != 'N' ):
        try:
            sendp(attr1_pkt, iface='eth0')
            sendp(attr2_pkt, iface='h1-eth1')
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()
        e = str(input("Enviar (S/N)?"))

if __name__ == '__main__':
    main()
