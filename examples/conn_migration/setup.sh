#! /bin/bash -xe

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

function start() {
  # Create nodes
  ip netns add node1
  ip netns add node2
  ip netns add node3

  # Create links
  ip link add eth-n2 netns node1 type veth peer eth-n1 netns node2
  ip link add eth-n3 netns node1 type veth peer eth-n1 netns node3
  ip link add eth-n2 netns node3 type veth peer eth-n3 netns node2

  # setup node1 ifaces
  ip -n node1 link set dev lo up
  ip -n node1 addr add 192.168.12.1/24 dev eth-n2
  ip -n node1 link set dev eth-n2 up
  ip -n node1 addr add 192.168.13.1/24 dev eth-n3
  ip -n node1 link set dev eth-n3 up

  # setup node2 ifaces
  ip -n node2 link set dev lo up
  ip -n node2 addr add 192.168.12.2/24 dev eth-n1
  ip -n node2 link set dev eth-n1 up
  ip -n node2 addr add 192.168.23.2/24 dev eth-n3
  ip -n node2 link set dev eth-n3 up

  # setup node3 ifaces
  ip -n node3 link set dev lo up
  ip -n node3 addr add 192.168.13.3/24 dev eth-n1
  ip -n node3 link set dev eth-n1 up
  ip -n node3 addr add 192.168.23.3/24 dev eth-n2
  ip -n node3 link set dev eth-n2 up

  # set routes to node2 on node1
  ip -n node1 route add 192.168.23.0/24 via 192.168.13.3 src 192.168.13.1

  #set routes to node1 on node2
  ip -n node2 route add 192.168.13.0/24 via 192.168.23.3 src 192.168.23.2

  # setup ip forwarding on node1 & node2
  ip netns exec node3 sysctl net.ipv4.ip_forward=1
  ip netns exec node3 sysctl net.ipv6.conf.all.forwarding=1
}

function teardown() {
  ip netns del node1
  ip netns del node2
  ip netns del node3
}

case $1 in
  start)
    start
    ;;

  teardown)
    teardown
    ;;

  restart)
    teardown
    start
    ;;

  *)
    echo "Usage: $0 (start|teardown|restart)"
    exit 1
    ;;
esac
