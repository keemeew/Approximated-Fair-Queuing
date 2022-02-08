from scapy.all import *
from kamene.all import *
from time import sleep
import sys
import matplotlib.pyplot as plt

spkt = []
five_tuple = []
srcpkt = rdpcap("/home/keemee/fair_queuing/dataset_00000_20091218012604.pcap")
f = open("flow_start.txt",'w')

for i in range (0,len(srcpkt)):
    srcAddr = srcpkt[i][IP].src
    dstAddr = srcpkt[i][IP].dst
    srcport = srcpkt[i][TCP].sport
    dstport = srcpkt[i][TCP].dport
    tuple_data = (srcAddr,dstAddr,srcport,dstport)
    if tuple_data not in five_tuple:
        five_tuple.append(tuple_data)
    pkt = Ether() / IP(src=srcAddr, dst=dstAddr) / TCP(sport=srcport, dport=dstport, seq=1) / 'hello world!'
    spkt.append(pkt)

for i in range(0,len(spkt)): 
    if (spkt[i][IP].src,spkt[i][IP].dst,srcpkt[i][TCP].sport,srcpkt[i][TCP].dport) in five_tuple:
        five_tuple.remove((spkt[i][IP].src,spkt[i][IP].dst,srcpkt[i][TCP].sport,srcpkt[i][TCP].dport))
        f.write(str(time.time())+"\n")
    sendp(spkt[i],iface='veth0',verbose=True)