#!/bin/bash
source .env

DOCKER_IF_IP="192.168.87.249/32"   # specify a single IP for routing
DOCKER_IF_RANGE="192.168.87.64/26"

ip link add signalrouteif link ${NETIF:-wlp0s20f3} type macvlan mode bridge &&
ip addr add ${DOCKER_IF_IP} dev signalrouteif &&
ip link set signalrouteif up &&
ip route add ${DOCKER_IF_RANGE} dev signalrouteif
