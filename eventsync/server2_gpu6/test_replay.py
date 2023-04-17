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

ordered_list = []

#iface_ = "enp1s0np1"
iface_ = "enp101s0f1"

def handle_unorder_pkt(pkt):
    sys.stdout.flush()
    print("got something")
    pkt2 =  Ether(src=get_if_hwaddr(iface_), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
    pkt2 = pkt2 / GvtProtocol(type=TYPE_REPLAY, value=pkt[GvtProtocol].value, pid=0, round =pkt[GvtProtocol].round)
    sendp(pkt2, iface=iface_, verbose=False)
    sys.stdout.flush()

def receive_unordered():
    #if receives something out of order, replay again
    sys.stdout.flush()
    build_lfilter = lambda r: GvtProtocol in r and r[GvtProtocol].type == TYPE_UNORDERED
    sniff(iface = iface_, lfilter = build_lfilter,prn = lambda x: handle_unorder_pkt(x))

def handle_last_pkt(pkt):
    sys.stdout.flush()
    print("got the last packet")
    sys.stdout.flush()   
    print(time.time() - initial)


def handle_ack_pkt(pkt):
    sys.stdout.flush()
    i = ordered_list.pop(0)
    print("send next")
    pkt =  Ether(src=get_if_hwaddr(iface_), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
    pkt = pkt / GvtProtocol(type=TYPE_REPLAY, value=0, pid=0, round=i)
    sendp(pkt, iface=iface_, verbose=False)        
    sys.stdout.flush()   

def receive_lastone():
    #if receives something out of order, replay again
    sys.stdout.flush()
    build_lfilter = lambda r: GvtProtocol in r and r[GvtProtocol].type == 10
    sniff(iface = iface_, lfilter = build_lfilter,prn = lambda x: handle_last_pkt(x))

def receive_ack():
    sys.stdout.flush()
    build_lfilter = lambda r: GvtProtocol in r and r[GvtProtocol].type == 15
    sniff(iface = iface_, lfilter = build_lfilter,prn = lambda x: handle_ack_pkt(x))    
    

new_rec_gather = Thread(target=receive_unordered)
new_rec_gather.start()

new_rec_last = Thread(target=receive_lastone)
new_rec_last.start()

new_rec_ack = Thread(target=receive_ack)
new_rec_ack.start()

#initial = time.time()

#for i in range(1,11):
#    if i%2 != 0:
#        ordered_list.append(i)

initial = time.time()

for i in range(1,10001):
    if i%2 != 0:
        pkt =  Ether(src=get_if_hwaddr(iface_), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
        pkt = pkt / GvtProtocol(type=TYPE_REPLAY, value=0, pid=0, round=i)
        sendp(pkt, iface=iface_, verbose=False)  
