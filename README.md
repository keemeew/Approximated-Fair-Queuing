# Approximated Fair Queuing implemented on Bmv2

This is simple implementation of "Approximated Fair Queuing (NSDI' 18)" on P4 v1model. 
Paper link: https://www.usenix.org/system/files/conference/nsdi18/nsdi18-sharma.pdf

## Dependencies

To run the code, basic dependencies such as Bmv2 and p4c should be installed. In addition, this code uses strict priority queue on v1model, which requires several modiifications and recompilation of the Bmv2 and p4c backends. I post links for detailed information below.

Bmv2: https://github.com/p4lang/behavioral-model

p4c: https://github.com/p4lang/p4c

Instructions for priority queuing: https://github.com/nsg-ethz/p4-learning/tree/master/examples/multiqueueing

## Instructions

This repository aims to implement basic concepts of AFQ using count-min sketch and recirculation. It keeps tacking departure rounds for each flows using count-min sketch with 5 tuple information. Due to the seperated structure of ingress and egress pipeline, we use periodic recirculation to synchronize registers between ingress & egress. Priority of the packet is decided by current flow departure rounds, which increase/decrease as a packet passes ingress/egress pipeline.

These are instructions you can follow to run.

1. Clone the repository to local 
```
git clone https://github.com/keemeew/Approximated-Fair-Queuing
```

2. Compile approx_fair_queuing.p4 (Optional)
```
p4c --target bmv2 --arch v1model approx_fair_queuing.p4
```

3. Set up virtual nic interfaces
```
sudo bash veth_setup.sh
```

4. Run Bmv2 switch 
```
sudo simple_switch -i 0@veth0 -i 1@veth2 -i 2@veth4 --log-console --thrift-port 9090 approx_fair_queuing.json
```
* 'veth0-2' is used for input port, and 'veth4' is output port.

5. Insert switch rule
```
sudo simple_switch_CLI --thrift-port 9090 < rule.txt
```

6. Send long flow and burst flow simultaneously
``` 
sudo python3 send.py --dst "10.10.0.1"
sudo python3 send.py --dst "10.10.0.2"
```
I recommend you to use terminal applications (e.g., terminator) which supports command broadcasting to run two different send.py commands simultaneously. Timing to send long flow and burst flow is carefully adjusted in python script. By the way, please sniff 'veth4 using packet sniffing applications such as wireshark by yourself.