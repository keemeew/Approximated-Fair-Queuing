from scapy.all import sniff
from kamene.all import *
from time import sleep
import sys
import matplotlib.pyplot as plt

def handle_pkt(packet):
    print(packet.show())
    if TCP in packet:
        protocol = packet.proto
        srcAddr = packet[IP].src
        dstAddr = packet[IP].dst
        L4src = packet[TCP].sport
        L4dst = packet[TCP].dport
        fivetuple = (protocol,srcAddr,dstAddr,L4src,L4dst)
        for k in range (0,len(flowlist)):
            if flowlist[k][0] == fivetuple:
                flowlist[k][1] -= 1
            
                if flowlist[k][1] <= 0:
                    flowlist[k][2] = time.time()

f = open("flow_end.txt",'w')
pkts = rdpcap("/home/keemee/fair_queuing/dataset_00000_20091218012604.pcap")

global flowlist, cplist, FCT

flowlist = []
cplist = []
FCT = []

for i in range (0,len(pkts)):
    if TCP in pkts[i]:
        protocol = pkts[i].proto
        srcAddr = pkts[i][IP].src
        dstAddr = pkts[i][IP].dst
        L4src = pkts[i][TCP].sport
        L4dst = pkts[i][TCP].dport
        fivetuple = (protocol,srcAddr,dstAddr,L4src,L4dst)
        flowdata = [fivetuple,1,0]
        if i==0:
            flowlist.append(flowdata)
        else:
            for k in range(0,len(flowlist)):
                if flowlist[k][0] == fivetuple:
                    flowlist[k][1] += 1
                    break
                elif k == len(flowlist)-1:
                    flowlist.append(flowdata)

for i in range (0,len(flowlist)):
    cplist.append(flowlist[i][1])



iface = 'veth2'
print("sniffing on %s" % iface)
sys.stdout.flush()
sniff(iface = iface, prn = lambda x: handle_pkt(x))
for i in range (0,len(flowlist)):
    print(flowlist[i][2])
    f.write(str(flowlist[i][2])+"\n")