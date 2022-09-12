#! /bin/bash -xe

# Create nodes
ip netns add node0
ip netns add node1

# Create p2p link
ip -n node0 l add veth0 type veth peer name veth1
ip -n node0 l set dev veth1 netns node1

# Setup interfaces
ip -n node0 l set dev lo up
ip -n node0 l set dev veth0 up

ip -n node1 l set dev lo up
ip -n node1 l set dev veth1 up

# Launch NDP
#ip netns exec node0 ../../build/examples/ndp/quic_sock_example_ndp &
#ip netns exec node1 ../../build/examples/ndp/quic_sock_example_ndp &
