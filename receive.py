from scapy.all import sniff
from kamene.all import *
from time import sleep
import sys
import matplotlib.pyplot as plt
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--nic', help='sniffing nic interface', type=str, required=True)
args= parser.parse_args()
nic = args.nic

def handle_pkt(packet):
    global flowlist, cnt
    if TCP in packet:
        print(packet[TCP].seq)
        cnt += 1
        protocol = packet.proto
        srcAddr = packet[IP].src
        dstAddr = packet[IP].dst
        L4src = packet[TCP].sport
        L4dst = packet[TCP].dport
        fivetuple = (protocol,srcAddr,dstAddr,L4src,L4dst)
        if nic == 'veth2':
            for k in range (0,len(flowlist)):
                if flowlist[k][0] == fivetuple:
                    flowlist[k][1] -= 1
                    if flowlist[k][1] <= 0:
                        flowlist[k][2] = cnt
        else:
            for k in range (0,len(flowlist)):
                if flowlist[k][0] == fivetuple:
                    if flowlist[k][1] == 1:
                        flowlist[k][2] = cnt
                        flowlist[k][1] -= 1

if nic == 'veth2':
    f = open("flow_end.txt",'w')
else:
    f = open("flow_start.txt",'w')

pkts = rdpcap("/home/keemee/Approximated-Fair-Queuing/dataset_1000.pcap")

global flowlist, cnt

flowlist = []
cnt = 0

for i in range (0,len(pkts)):
    if TCP in pkts[i]:
        protocol = pkts[i].proto
        srcAddr = pkts[i][IP].src
        dstAddr = pkts[i][IP].dst
        L4src = pkts[i][TCP].sport
        L4dst = pkts[i][TCP].dport
        fivetuple = (protocol,srcAddr,dstAddr,L4src,L4dst)
        flowdata = [fivetuple,1,0]
        if i == 0:
            flowlist.append(flowdata)
        else:
            for k in range(0,len(flowlist)):
                if flowlist[k][0] == fivetuple:
                    if nic == 'veth2':
                        flowlist[k][1] += 1
                    break
                elif k == len(flowlist)-1:
                    flowlist.append(flowdata)

print(flowlist)
print(len(flowlist))
iface = nic
print("sniffing on %s" % iface)
sys.stdout.flush()
sniff(iface = iface, prn = lambda x: handle_pkt(x))
for i in range (0,len(flowlist)):
    print(flowlist[i][2])
    f.write(str(flowlist[i][2])+"\n")