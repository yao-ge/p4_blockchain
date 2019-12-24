#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

timestamp_list = []

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt):
    #if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt and pkt[UDP].dport == 1234 and pkt.ttl != 64:
        print("got a packet")
        #pkt.show2()
        #hexdump(pkt)
        data_load = pkt.load
        request_type = data_load[:1]
        nodes_count = data_load[1:2]
        block_count = data_load[2:6]
        pre_header_hash = data_load[6:38]
        curr_header_hash = data_load[38:70]
        data_hash = data_load[70:102]
        timestamp = data_load[102:106]
        nonce = data_load[106:110]
        data_str = data_load[110:179]
        print("request type:", request_type)
        print("nodes count:", struct.unpack("B", nodes_count)[0])
        print("block count:", struct.unpack(">I", block_count)[0])
        print("pre header hash:", pre_header_hash.encode('hex'))
        print("curr header hash:", curr_header_hash.encode('hex'))
        print("data hash:", data_hash.encode('hex'))
        print("timestamp:", struct.unpack(">I", timestamp)[0])
        print("nonce:", struct.unpack(">I", nonce)[0])
        print("\n")
        sys.stdout.flush()
        if pkt.load.startswith('e'):
            exit(0)

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
