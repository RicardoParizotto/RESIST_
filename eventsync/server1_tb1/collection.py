#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import ast

from threading import Thread

from scapy.all import sniff, sendp, Raw

import numpy as np

import argparse,sys,time,os

from scapy.all import (
    BitField,
    BitEnumField,
    Packet,
    SignedIntField,
    bind_layers,
    UDP,
    Ether,
    IP,
    get_if_addr,
    get_if_hwaddr,
    conf,
)

iface_ = "enp1s0np1"
#iface_ = "enp101s0f1"

BASE_PKT = (
    Ether(src="00:15:4d:12:11:a9", dst=get_if_hwaddr(conf.iface))
    / IP(dst="10.50.1.6", src=get_if_addr(conf.iface))
    / UDP(sport=8000, dport=8000)
)

class determinantsCollection:
    def __init__(self, veth1):  
        self.iface_ = veth1
        self.max_value = 0;
        self.content = []  
        self.new_rec_gather = Thread(target=self.receive_report)
        self.new_rec_gather.start()
    def handle_report(self, pkt):
        sys.stdout.flush()
        content = (pkt[Raw].load).decode("utf-8")
        self.content = ast.literal_eval(content)
        self.max_value = max(int(value) for (id, round, value) in self.content)
        sys.stdout.flush()   
    def receive_report(self):
        #if receives something out of order, replay again
        sys.stdout.flush()
        build_lfilter = lambda r: IP in r and r[IP].dst == "10.50.1.6"
        sniff(iface = self.iface_, lfilter = build_lfilter,prn = lambda x: self.handle_report(x))
    #this is the list of determinants i am sending to the other host
    def send_determinants(self, list):
        pkt = BASE_PKT / Raw(load=str(list))
        pkt.show2()
        sendp(pkt, iface=self.iface_, verbose=False)
    def get_max():
        return self.max_value
    def get_content():
        return self.content

#det = determinantsCollection(iface_)    
#det.send_determinants([(1, 2, 3), (1, 5, 1)])
