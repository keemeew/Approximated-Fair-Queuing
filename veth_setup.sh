#!/bin/bash

ip link add name veth0 type veth peer name veth1
ip link add name veth2 type veth peer name veth3
ip link add name veth4 type veth peer name veth5
ip link add name veth6 type veth peer name veth7
ip link add name veth8 type veth peer name veth9
ip link add name veth10 type veth peer name veth11
ip link set dev veth0 up
ip link set dev veth1 up
ip link set dev veth2 up
ip link set dev veth3 up
ip link set dev veth4 up
ip link set dev veth5 up
ip link set dev veth6 up
ip link set dev veth7 up
ip link set dev veth8 up
ip link set dev veth9 up
ip link set dev veth10 up
ip link set dev veth11 up
