
#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import ast

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw
from gvt_header_l2 import GvtProtocol

from threading import Thread

from scapy.all import sniff

import numpy as np

import argparse,sys,time,os


ETHERTYPE_GVT = 0x8666
TYPE_PROPOSAL = 1
TYPE_DELIVER = 0
TYPE_FAILURE = 2
TYPE_DELFAILURE = 3
TYPE_REPLAY = 4
TYPE_UNORDERED = 5
TYPE_COLLECT = 6

class gvtControl:
    def __init__(self, pid, veth1, veth2, size):

        self.gvt = 0
        self.start_ppkt = 0
        self.pid = pid
        self.lat = np.array([])
  
        self.second_start = 0
        self.pkts_per_second = 0
        self.pkts_last_second = 0

        self.rps = []

        self.in_list = []

        #variables for failures
        self.round_failure = 0
        self.lvt_failure = 0
        self.svr_determinants = []        

        self.iface = veth1
        self.iface2 = veth2
        self.leader_alive = 1

        self.total_time = size

        self.new_rec_thread = Thread(target=self.receive)
        self.new_rec_thread.start()

        self.logical_clocks = [0, 0]
        self.GVT = 0

    def handle_pkt(self, pkt):
        sys.stdout.flush()

        self.logical_clocks[pkt[GvtProtocol].pid] = pkt[GvtProtocol].value

        self.GVT = min(self.logical_clocks)

        print("got it")

        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
        pkt = pkt / GvtProtocol(type=TYPE_DELIVER, value=self.GVT, pid=pkt[GvtProtocol].pid, round=0)

        sendp(pkt, iface=self.iface, verbose=False)

        sys.stdout.flush()

    #this is for receiving new GVT values
    def receive(self):
    	sys.stdout.flush()
    	build_lfilter = lambda r: GvtProtocol in r and r[GvtProtocol].type == TYPE_PROPOSAL
    	sniff(iface = self.iface, lfilter = build_lfilter, prn = lambda x: self.handle_pkt(x))


def get_args():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--pid", type=int)

    parser.add_argument("--veth1", type=str)
    parser.add_argument("--veth2", type=str)
 
    parser.add_argument("--size", type=str)

    return parser.parse_args()

if __name__ == '__main__':
    args = get_args()    

    GVTcontrol_instance = gvtControl(args.pid, args.veth1, args.veth2, args.size)
