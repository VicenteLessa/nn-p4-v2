#!/usr/bin/env python

from ANN_hdrs import *

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_pkt(pkt):
    if ann in pkt:
        print(pkt[ann].__repr__())


def main():
    iface = 'eth0'
    print("sniffing on {}".format(iface))
    sniff(iface = iface, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
