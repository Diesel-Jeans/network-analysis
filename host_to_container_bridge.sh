#!/bin/bash

HOST_IF="wlp0s20f3"                # change to your network interface
DOCKER_IF_IP="192.168.87.249/32"   # specify a single IP for routing
DOCKER_IF_RANGE="192.168.87.64/26"

ip link add signalrouteif link ${HOST_IF} type ipvlan mode l2 bridge &&
ip addr add ${DOCKER_IF_IP} dev signalrouteif &&
ip link set signalrouteif up &&
ip route add ${DOCKER_IF_RANGE} dev signalrouteif
