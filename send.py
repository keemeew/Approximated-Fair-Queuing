from scapy.all import *
from kamene.all import *
from time import sleep
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--dst', help='flow destination', type=str, required=True)
args= parser.parse_args()
dst = args.dst

spkt = []
five_tuple = []
cnt = 0
pps = 0
num = 0
wait_time = 0
veth = ''

if dst == "10.10.0.1":
    num = 750
    pps = 200
    wait_time = 0
    veth = 'veth0'
elif dst == "10.10.0.3":
    num = 450
    pps = 200
    wait_time = 1.2
else:
    num = 100
    pps = 100
    wait_time = 3
    veth = 'veth2'

for i in range (0,num):
    cnt += 1
    srcAddr = "192.168.10.1"
    dstAddr = dst
    srcport = 111
    dstport = 222
    pkt = Ether() / IP(src=srcAddr, dst=dstAddr) / TCP(sport=srcport, dport=dstport, seq=1) / 'hello world!'
    spkt.append(pkt)

sleep(wait_time)
sendpfast(spkt,iface='veth2',verbose=True,pps=pps)