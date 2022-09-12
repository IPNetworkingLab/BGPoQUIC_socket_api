#! /bin/bash -xe

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# make sure that link is up
ip link set dev eth-n2 up

# launch client in background
./client_migration 192.168.12.2 192.168.23.2 8989 ../ndp/certs/client_cert.crt ../ndp/certs/client_key.key 192.168.13.1 oui &

# sleep 1 second
sleep 1

# set direct link with server
ip link set dev eth-n2 down