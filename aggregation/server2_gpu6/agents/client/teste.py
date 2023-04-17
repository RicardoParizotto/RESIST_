import matplotlib

matplotlib.use("Agg")

from scapy.all import sendp, srp, srp1, conf, Ether, IP, UDP
import torch
import time
from protocol import Gradient, SspHeader, assemble_pkt, unquantize
from scapy.all import sniff


CHUNK_SIZE = 500
conf.use_pcap = True
conf.verb = 0
conf.layers.filter([Ether, IP, UDP, SspHeader, Gradient])
conf.checkIPaddr = False

pkts = assemble_pkt(1, 1, 1, "read_row")


res, nres = srp(pkts, timeout=3, iface = "enp101s0f1", retry=-1, filter="udp")
