Usage: generator --help
run --pci <pci-addr> --tap <interface> --mac <mac address> \
    --ip <ipv4 address> --port <port number> --count <count> \
    --size <payload size> [-D <seconds>] [-v] [-d]

  --pci    <pci-addr>      PCI device number for NIC
  --tap    <tap interface> tap interface to use instead of a real NIC
  --mac    <mac address>   Ethernet destination address (next-hop to use)
  --ip     <ip address>    IPv4 destination address to start with 
  --port   <port number>   UDP port number to start with
  --size   <payload size>  UDP payload size in bytes
  -D       <seconds>       Duration in seconds
  -v                       show load report every second
  -d                       show per-packet information. -d -d adds interpacket delay

Generate lw4o6 IPv4 traffic, starting with given IP address and UDP port number.
Port is incremented by the given port number and port rollovers increment the IP address.

Example
sudo ./snabb snabbvmx generator --pci 0000:04:00.0 --mac 02:8C:71:87:00:02 --ip 193.5.1.100 --count 100 --port 1024 --size 100 -d -d

Generates 
sending packet for 193.5.1.100 port 1024 payload 100 bytes
sending packet for 193.5.1.100 port 2048 payload 100 bytes
sending packet for 193.5.1.100 port 3072 payload 100 bytes
sending packet for 193.5.1.100 port 4096 payload 100 bytes
sending packet for 193.5.1.100 port 5120 payload 100 bytes
sending packet for 193.5.1.100 port 6144 payload 100 bytes
...
sending packet for 193.5.1.100 port 63488 payload 100 bytes
sending packet for 193.5.1.100 port 64512 payload 100 bytes
sending packet for 193.5.1.101 port 1024 payload 100 bytes
sending packet for 193.5.1.101 port 2048 payload 100 bytes
sending packet for 193.5.1.101 port 3072 payload 100 bytes
...