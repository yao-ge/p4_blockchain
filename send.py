#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    payload = sys.argv[2] + '0' * 32
    pkt = pkt /IP(dst=addr) / UDP(dport=1234, sport=random.randint(49152,65535)) / payload
    #pk_string = '\x00\x00\xFF\xFF\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x6F\x14\x01\x01\x01'
    #pk_string = '\x00\x00\x00\x00\x6F\x14'
    #pkt = pkt /IP(dst=addr) / UDP(dport=1234, sport=random.randint(49152,65535)) / pk_string
    pkt.show2()
    hexdump(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
