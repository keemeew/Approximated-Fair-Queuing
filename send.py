from scapy.all import *
from kamene.all import *
from time import sleep
import sys

spkt = []
five_tuple = []
cnt = 0
srcpkt = rdpcap("/home/keemee/Approximated-Fair-Queuing/dataset_1000.pcap")
f = open("flow_start.txt",'w')

for i in range (0,len(srcpkt)):
    cnt += 1
    srcAddr = srcpkt[i][IP].src
    dstAddr = srcpkt[i][IP].dst
    srcport = srcpkt[i][TCP].sport
    dstport = srcpkt[i][TCP].dport
    tuple_data = (srcAddr,dstAddr,srcport,dstport)
    if tuple_data not in five_tuple:
        five_tuple.append(tuple_data)
    pkt = Ether() / IP(src=srcAddr, dst=dstAddr) / TCP(sport=srcport, dport=dstport, seq=cnt) / 'hello world!'
    spkt.append(pkt)

sendpfast(spkt,iface='veth4',verbose=True,pps=1000)