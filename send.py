#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, UDP, TCP

pre_header_hash = '\0' * 32
data_string = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    if len(sys.argv)<1:
        print ('pass 1 arguments: <destination>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print ("sending on interface %s to %s" % (iface, str(addr)))


    while True:
        request_string = raw_input("\n\033[31mread[r]/\033[32mwrite[w]/\033[33minit[i]/\033[34mexit[e]\n\033[37mrequest:")
        if 'r' == request_string or 'read' == request_string:
            payload = 'r' + '\0' * 32 + '\0' * 69
        elif 'i' == request_string or 'init' == request_string:
            payload = 'i' + '\0' * 32 + '\0' * 69
        elif 'w' == request_string or 'write' == request_string:
            payload = 'w' + pre_header_hash + data_string
        elif 'e' == request_string or 'exit' == request_string:
            payload = 'e' + '\0' * 32 + '\0' * 69

        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt /IP(dst=addr) / UDP(dport=1234, sport=random.randint(49152,65535)) / payload
        pkt.show2()
        hexdump(pkt)
        sendp(pkt, iface=iface, verbose=False)

        if 'e' == request_string or 'exit' == request_string:
            break;


if __name__ == '__main__':
    main()
