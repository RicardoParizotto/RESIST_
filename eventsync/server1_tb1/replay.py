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
TYPE_PROPOSAL = 10
TYPE_DELIVER = 0
TYPE_FAILURE = 2
TYPE_DELFAILURE = 3
TYPE_REPLAY = 4
TYPE_UNORDERED = 5
TYPE_COLLECT = 6


initial = time.time()

iface_ = "enp1s0np1"
#iface_ = "enp101s0f1"

unordered = 0

pkt_base =  Ether(src=get_if_hwaddr(iface_), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
pkt_base = pkt_base / GvtProtocol(type=TYPE_REPLAY, value=0, pid=0, round=1)

#this class packets sends packets with values from the ordered list
#to start the replay is necessary to replay the first packet
class strongReplay:
    def __init__(self, ith1):
        self.iface_ = ith1        
        self.ordered_list = []
        self.new_rec_gather = Thread(target=self.receive_unordered)
        self.new_rec_gather.start()
        self.new_rec_last = Thread(target=self.receive_lastone)
        self.new_rec_last.start()
        self.new_rec_ack = Thread(target=self.receive_ack)
        self.new_rec_ack.start()
        self.unordered = 0
    def handle_unorder_pkt(self, pkt):
        sys.stdout.flush()
        print("got something")
        pkt2 =  Ether(src=get_if_hwaddr(self.iface_), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
        pkt2 = pkt2 / GvtProtocol(type=TYPE_REPLAY, value=pkt[GvtProtocol].value, pid=pkt[GvtProtocol].pid, round =pkt[GvtProtocol].round)
        sendp(pkt2, iface=self.iface_, verbose=False)
        sys.stdout.flush()
        self.unordered = self.unordered + 1
        print(self.unordered)
    def receive_unordered(self):
        #if receives something out of order, replay again
        sys.stdout.flush()
        build_lfilter = lambda r: GvtProtocol in r and r[GvtProtocol].type == TYPE_UNORDERED
        sniff(iface = self.iface_, lfilter = build_lfilter,prn = lambda x: self.handle_unorder_pkt(x))
    def handle_last_pkt(self, pkt):
        sys.stdout.flush()
        print("got the last packet")
        sys.stdout.flush()   
        print(time.time() - initial)
    def handle_ack_pkt(self, pkt):
        sys.stdout.flush()
        i = self.ordered_list.pop(0)
        id, round, value = i
        pkt_base[GvtProtocol].round = round
        pkt_base[GvtProtocol].value = value
        pkt_base[GvtProtocol].pid = id
        sendp(pkt_base, iface=self.iface_, verbose=False)        
        sys.stdout.flush()   
    def receive_lastone(self):
        #if receives something out of order, replay again
        sys.stdout.flush()
        build_lfilter = lambda r: GvtProtocol in r and r[GvtProtocol].type == 10
        sniff(iface = self.iface_, lfilter = build_lfilter,prn = lambda x: self.handle_last_pkt(x))
    def receive_ack(self):
        sys.stdout.flush()
        build_lfilter = lambda r: GvtProtocol in r and r[GvtProtocol].type == 15
        sniff(iface = self.iface_, lfilter = build_lfilter,prn = lambda x: self.handle_ack_pkt(x))  
    def start_replay(self, max_, determinants):
        #TODO:the max value is to define the end of replaying. 
        #TODO:need to reconfigure the switch for _replay.execute and replay_counter based on MAX 
        self.ordered_list = determinants
        i = self.ordered_list.pop(0)
        id, round, value = i
        pkt_base[GvtProtocol].round = round
        pkt_base[GvtProtocol].value = value
        pkt_base[GvtProtocol].pid = id
        sendp(pkt_base, iface=iface_, verbose=False)   


teste = strongReplay(iface_)
for i in range(2,102):
    if i % 2 == 0:
        teste.ordered_list.append([i, 10, 0]) 

initial = time.time()
pkt_base[GvtProtocol].round = 1
sendp(pkt_base, iface=iface_, verbose=False)        
teste.start_replay(10,teste.ordered_list)
