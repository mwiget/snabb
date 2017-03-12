Usage: lwaftrgen --help

run --conf <config-file> --id <port-id> --pci <pci-addr> --mac <mac-address> \
    --sock <socket-path> [-D <seconds>] [-v]

Arguments:

  --conf    <config-file>   configuration file for lwaftr service
  --id      <port-id>       port_id for virtio socket
  --pci     <pci-addr>      PCI device number for NIC (or Linux interface name)
  --mac     <mac address>   Ethernet address of virtio interface
  --sock    <socket-path>   Socket path for virtio-user interfaces

Optional:

  -D        <seconds>       Duration in seconds
  -v                        Verbose (repeat for more verbosity)

Example config file:

# cat snabbvmx-lwaftr-xe0.cfg
return {
   lwaftrgen = "snabbvmx-lwaftrgen-xe0.conf",
   ipv6_interface = {
     cache_refresh_interval = 1,
   },
   ipv4_interface = {
     ipv4_address = "10.0.1.1",
     cache_refresh_interval = 1,
   },
   settings = {},
}

and the referenced 'lwaftrgen.conf' file:

# cat lwaftrgen.conf
vlan_tagging = false,
dst_mac = 02:99:99:99:99:99,
count = 60000,
aftr_ipv6 = fc00::100,
rate = 3148,
b4_ipv6 = 2001:db8::40,
public_ipv4 = 10.10.0.0,
b4_ipv4 = 8.8.8.8,
b4_port = 1024,
