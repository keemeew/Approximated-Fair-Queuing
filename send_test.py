from scapy.all import sendp
from kamene.all import *
from time import sleep
import sys
import matplotlib.pyplot as plt

time = []
intial_time = 0

pkts = rdpcap("/home/keemee/fair_queuing/dataset.pcap")

for i in range (0,len(pkts)):

    if i == 0:
        intial_time = pkts[i].time    
    time.append(pkts[i].time-intial_time)

#for i in range (0,len(pkts)):
sendp(pkts,iface='veth0',verbose=True)
'''
for i in range (0,len(pkts)):    
    sleep(time[i])
    sendp(pkts[i],iface='veth0',verbose=True)
'''