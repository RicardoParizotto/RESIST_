
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

import argparse,sys,time,os, psutil


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

        self.process = psutil.Process()
        self.initial_mem = self.process.memory_info().rss



        #those two are for strong consistency
        self.input_list = []
        self.output_list = []

        self.iface = veth1
        self.iface2 = veth2
        self.leader_alive = 1

        self.total_time = size

        self.new_rec_thread = Thread(target=self.receive)
        self.new_rec_thread.start()

        self.new_send_thread = Thread(target=self.send)
        self.new_send_thread.start()

        self.new_send_ping = Thread(target=self.aliveThread)
        self.new_send_ping.start()

        self.new_rec_pong = Thread(target=self.receive_pong)
        self.new_rec_pong.start()

        self.new_second_thread = Thread(target=self.counter)
        self.new_second_thread.start()

        self.new_send_lost = Thread(target = self.resend_lost_packets)
        self.new_send_lost.start()

        self.gb = Thread(target = self.garbage_collection)
        self.gb.start()

    def garbage_collection(self):
        interval = 5
        #TODO: change interval according to switch clocks/rounds
        time.sleep(interval)
        del self.in_list[:]


    #Netgvt
    def resend_lost_packets(self):
        while True:
            time.sleep(5) 
            now = time.time()
            
            #just sends again a message if it didn't received and ACK
            for (logical, real_time) in self.in_list:
                if (now - real_time > 5):
                    pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
                    pkt = pkt / GvtProtocol(type=TYPE_PROPOSAL, value=logical, pid=self.pid, round=0) 

    def counter(self):
        while(1):
            time.sleep(1)
            self.rps.append(self.pkts_last_second)
            self.pkts_last_second = 0

    def handle_pkt(self, pkt):
        sys.stdout.flush()

        end = time.time()

        print self.process.memory_info().rss - self.initial_mem
        #time of request update  
        #print end - self.start_ppkt
        if(end - self.second_start > 1):
            self.second_start = end
            #print RPS
            #print (self.pkts_per_second)
            self.pkts_last_second = self.pkts_per_second
            self.pkts_per_second = 0
        else:
            self.pkts_per_second = self.pkts_per_second + 1
 
        #this condition is complex check if it works
        if(pkt[GvtProtocol].pid == self.pid and ((pkt[GvtProtocol].value) in ([item[0] for item in self.in_list]))):
            for element in self.in_list:
                if (element[0] == pkt[GvtProtocol].value):
                    self.in_list.remove(element)
        elif(pkt[GvtProtocol].pid != self.pid):
            #store to be used for recovery. Just in case is from other shim layers
            self.output_list.append((pkt[GvtProtocol].pid, pkt[GvtProtocol].value, pkt[GvtProtocol].round))   
        self.gvt = pkt[GvtProtocol].value
        sys.stdout.flush()

    def handle_pong_pkt(self,pkt):
        sys.stdout.flush()
        #print('pong')
        self.leader_alive = 1
        sys.stdout.flush()

    def handle_gather_pkt(self,pkt):
        sys.stdout.flush()
        #mark the new round number for recovery
        self.round_failure = pkt[GvtProtocol].round
        #mark the lvt from last packet seen by the switch
        self.lvt_failure = pkt[GvtProtocol].value
        sys.stdout.flush()   

    def handle_unorder_pkt(self, pkt):
        sys.stdout.flush()

        pkt2 =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
        pkt2 = pkt2 / GvtProtocol(type=TYPE_REPLAY, value=pkt[GvtProtocol].value, pid=self.pid, round =pkt[GvtProtocol].round)
        sendp(pk2t, iface=self.iface, verbose=False)
        
        sys.stdout.flush()

    #this is for receiving new GVT values
    def receive(self):
    	sys.stdout.flush()
    	build_lfilter = lambda (r): GvtProtocol in r and r[GvtProtocol].type == TYPE_DELIVER
    	sniff(iface = self.iface, lfilter = build_lfilter, prn = lambda x: self.handle_pkt(x))

    def receive_pong(self):
        sys.stdout.flush()
        build_lfilter = lambda (r): GvtProtocol in r and r[GvtProtocol].type == TYPE_DELFAILURE
        sniff(iface = self.iface, lfilter = build_lfilter,prn = lambda x: self.handle_pong_pkt(x))
    
    #this is for receiving rounds from switch after failure
    def receive_gathering(self):
        sys.stdout.flush()
        build_lfilter = lambda (r): GvtProtocol in r and r[GvtProtocol].type == TYPE_COLLECT
        sniff(iface = self.iface, lfilter = build_lfilter,prn = lambda x: self.handle_gather_pkt(x))

    def receive_unordered(self):
        #if receives something out of order, replay again
        sys.stdout.flush()
        build_lfilter = lambda (r): GvtProtocol in r and r[GvtProtocol].type == TYPE_UNORDERED
        sniff(iface = self.iface, lfilter = build_lfilter,prn = lambda x: self.handle_unorder_pkt(x))


    def send(self):
        src_addr = socket.gethostbyname('10.50.1.1')
        dst_addr = socket.gethostbyname('10.50.0.100')
    
        lvt = 0
        end_simulation_loop = int(self.total_time)
        start = time.time()
        self.second_start
        while lvt < end_simulation_loop:
            if lvt <= self.gvt:
	        lvt = lvt + 1
                self.in_list.append((lvt, time.time()))
                self.input_list.append(lvt)
    	        #print "sending on interface %s to %s" % (iface, str(src_addr))
    	        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
    	        pkt = pkt / GvtProtocol(type=TYPE_PROPOSAL, value=lvt, pid=self.pid, round=0)
    	        #pkt.show2()
                self.start_ppkt = time.time()   
                sendp(pkt, iface=self.iface, verbose=False)

        end = time.time()
        print "total time: " + str(end-start)
        time.sleep(10) 

        os._exit(1)

    def weak_replay(self):
       try: 
            print(self.in_list)
            for (n, time) in self.in_list:
                pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
                pkt = pkt / GvtProtocol(type=TYPE_PROPOSAL, value=n, pid=self.pid, round=0)
                pkt.show2() 
                sendp(pkt, iface=self.iface, verbose=False)
       except:
            print('empty')


    def handle_received(self, pkt):
        #TODO: need to save the maximum value
        #save all the messages LVTs        
        #print ('do something')
        sys.stdout.flush()
        #convert output_list string into list
        self.srv_determinants = ast.literal_eval(pkt[UDP].load)
        #definir o max value e uma maneira para ler os rounds por pacote
        sys.stdout.flush()

    #this is for receiving determinants from the server
    def receive_server(self):
        sys.stdout.flush()
        build_lfilter = lambda (r): UDP in r
        sniff(iface = self.iface, lfilter = build_lfilter,prn = lambda x: handle_received(x))       	

    def send_determinants(self):
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst=get_if_hwaddr(self.iface))
        pkt = pkt /IP(src="10.50.1.1", dst="10.50.1.6") 
        pkt = pkt / UDP(dport=1234) / Raw(load=self.output_list)
        #pkt.show()
        send(pkt, iface=self.iface, verbose=False)
    #resist
    def strong_replay(self):
        #create gathering packet and start replay*/
      
        #this one is for receving collection from switches (round and lvt for the process)
        self.new_rec_gather = Thread(target=self.receive_gathering)
        self.new_rec_gather.start()
         
        #send a packet for gathering the round number from switches
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst=get_if_hwaddr(self.iface), type = ETHERTYPE_GVT)
        pkt = pkt / GvtProtocol(type=TYPE_COLLECT, value=0, pid=self.pid, round=0)
        sendp(pkt, iface=self.iface, verbose=False)
        #pkt.show2()

        #send determinants
        self.send_determinants()
        #gather from server
        self.new_rec_server = Thread(target=self.receive_server)
        self.new_rec_server.start()
        #create thread to receive ann replay out of order packets
        self.new_rec_unordered = Thread(target=self.receive_unordered)
        self.new_rec_unordered.start() 

        #now need to replay packets
        self.replay = Thread(target=self.replay_packets)
        self.replay.start()

    #this is resist stuff
    def replay_packets(self):
        #TODO: need a starting condition also: when are the variables initiated?
        try:
            self.maxVal = max(int(value) for (id, value, round) in self.svr_determinants)
        except:
            print('no max') 
        #for all pakets in output list
        
        try:
            for pkt in self.output_list:
                if pkt[GvtProtocol].value > self.lvt_failure and pkt[GvtProtocol].value < self.maxValue:
                    pkt[GvtProtocol].type = TYPE_REPLAY
                    #geting the round number which pkt was processed by neighbor
                    pkt[GvtProtocol].round = [round for (id, value, round) in self.svr_determinants if value == pkt[GvtProtocol].value] 
                    sendp(pkt, iface=self.iface, verbose=False)
        except:
            print('no pkt in outputlist') 
        #TODO: stop condition??? special packet?
                

    #this is also resist stuff
    def change_interface(self):
        begin = time.time()
        print(('PRIMARY TIMEOUT!!'))
        self.iface = self.iface2  #this is for using the other interface. Have to change for different testbed

        #----------------------retransmit---------------------# 
        self.new_rec_thread = Thread(target=self.receive)
        self.new_rec_thread.start()
         
        self.weak_replay()
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
                pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
                pkt = pkt / GvtProtocol(type=TYPE_FAILURE, value=0, pid=self.pid, round=0)
                sendp(pkt, iface=self.iface, verbose=False)           #this is a PING! leader alive?
                self.leader_alive = 0
                #print "ping"
            elif(failure_counter >5):
                #trigger recovery...
                self.change_interface()
                self.leader_alive = 1
                failure_counter = 0 #necessario para nao entrar nessa condicao logo que o novo leader e escolhido
                #envia pacote de start changeS
            #self.lock_alive.release()
            else:
                failure_counter = failure_counter + 1

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
