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
from protocol import Gradient, SspHeader, assemble_pkt, unquantize

from threading import Thread

from scapy.all import sniff

import numpy as np

import argparse,sys,time,os



class shimLayer:

    def __init__(self, pid, veth1, veth2):
        
        self.iface = veth1
        self.iface2 = veth2

        #self.new_send_ping = Thread(target=self.aliveThread)
        #self.new_send_ping.start()

        #self.new_rec_pong = Thread(target=self.receive_pong)
        #self.new_rec_pong.start()

        self.leader_alive = 1
    
    def get_if(self):
        return self.iface

    def handle_pong_pkt(self,pkt):
        sys.stdout.flush()
        print('pong')
        self.leader_alive = 1
        sys.stdout.flush()

    #4 is delfailure 
    def receive_pong(self):
        sys.stdout.flush()
        build_lfilter = lambda r: SspHeader in r and r[SspHeader].action == 4
        sniff(iface = self.iface, lfilter = build_lfilter,prn = lambda x: self.handle_pong_pkt(x))

    def change_interface(self):
        begin = time.time()
        print(('PRIMARY TIMEOUT!!'))
        self.iface = self.iface2  #this is for using the other interface. Have to change for different testbed

        #----------------------retransmit---------------------# 
        #self.new_rec_thread = Thread(target=self.receive)
        #self.new_rec_thread.start()
         
        #self.weak_replay()
        #self.strong_replay()            #TODO: need to make sure is receiving from the other server
        print('replay done')

        self.new_rec_pong = Thread(target=self.receive_pong)
        self.new_rec_pong.start()
        print('recovery time' + str(time.time() - begin)) 

    #this is Resist stuff
    def aliveThread(self):
        failure_counter = 0
        while True:
            time.sleep(5)
            #self.lock_alive.acquire()
            if(self.leader_alive == 1):
                print("leader")
                pkt = assemble_pkt(1, 1, 0, "failure") 
                sendp(pkt, iface=self.iface, verbose=False)           #this is a PING! leader alive?
                self.leader_alive = 0
            elif(failure_counter >5):
                #trigger recovery...
                self.change_interface()
                self.leader_alive = 1
                failure_counter = 0 #necessario para nao entrar nessa condicao logo que o novo leader e escolhido
                #envia pacote de start changeS
            #self.lock_alive.release()
            else:
                failure_counter = failure_counter + 1


