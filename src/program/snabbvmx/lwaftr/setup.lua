module(..., package.seeall)

local config     = require("core.config")
local pci        = require("lib.hardware.pci")
local VhostUser  = require("apps.vhost.vhost_user").VhostUser
local PcapFilter = require("apps.packet_filter.pcap_filter").PcapFilter
local lwaftr     = require("apps.lwaftr.lwaftr")
local basic_apps = require("apps.basic.basic_apps")
local pcap       = require("apps.pcap.pcap")
local bt         = require("apps.lwaftr.binding_table")
local ipv4_apps  = require("apps.lwaftr.ipv4_apps")
local ipv6_apps  = require("apps.lwaftr.ipv6_apps")
local ethernet   = require("lib.protocol.ethernet")
local nh_fwd     = require("apps.nh_fwd.nh_fwd")
local v4v6       = require("apps.nh_fwd.v4v6").v4v6
local tap        = require("apps.tap.tap")


function lwaftr_app(c, conf, lwconf, sock_path, vmxtap)

  assert(type(conf) == 'table')
  assert(type(lwconf) == 'table')
  assert(type(conf.ipv6_interface) == 'table')
  assert(type(conf.ipv4_interface) == 'table')

  print (string.format("vmxtap is set to %s (in lwaftr_app)", vmxtap))

  if lwconf.binding_table then
    conf.preloaded_binding_table = bt.load(lwconf.binding_table)
  end

  local phy_idv6 = "nic_" .. conf.ipv6_interface.id
  local phy_idv4 = "nic_" .. conf.ipv4_interface.id
  local mirror_id = conf.settings.mirror_id
  local virt_idv6 = "vmx_" .. conf.ipv6_interface.id
  local virt_idv4 = "vmx_" .. conf.ipv4_interface.id

  local device_info = pci.device_info(conf.ipv6_interface.pci)
  if not device_info then 
    fatal(("Couldn't find device info for PCI address '%s'"):format(conf.ipv6_interface.pci))
  end

  local vlan_v6 = tonumber(conf.ipv6_interface.vlan)
  print(string.format("%s ether %s", phy_idv6, conf.ipv6_interface.mac_address))
  if vlan_v6 then
    print(string.format("%s vlan %d", phy_idv6, vlan_6))
  end

  local vlan_v4 = tonumber(conf.ipv4_interface.vlan)
  print(string.format("%s ether %s", phy_idv4, conf.ipv4_interface.mac_address))
  if vlan_v4 then
     print(string.format("%s vlan %d", phy_idv4, vlan_v4))
  end

  print(string.format("discard check_timer=%d sec wait=%d sec threshold=%d packets/sec",
  conf.settings.discard_check_timer, conf.settings.discard_wait, conf.settings.discard_threshold))

  local qprdc = {}
  qprdc.discard_check_timer = conf.settings.discard_check_timer
  qprdc.discard_wait = conf.settings.discard_wait
  qprdc.discard_threshold = conf.settings.discard_threshold

  config.app(c, phy_idv4, require(device_info.driver).driver,
    { pciaddr = conf.ipv4_interface.pci, vmdq = true, vlan = vlan_v4, 
      macaddr = conf.ipv4_interface.mac_address, mtu = conf.ipv4_interface.mtu,
      qprdc = qprdc })
  local v4_output, v4_input = phy_idv4 .. ".tx", phy_idv4 .. ".rx"

  config.app(c, phy_idv6, require(device_info.driver).driver, 
    { pciaddr = conf.ipv6_interface.pci, vmdq = true, vlan = vlan_v6, 
      macaddr = conf.ipv6_interface.mac_address, mtu = conf.ipv6_interface.mtu,
      qprdc = qprdc })
  local v6_output, v6_input = phy_idv6 .. ".tx", phy_idv6 .. ".rx"


  if lwconf.hairpinning == true then
    print("hairpinning enabled")
  else
    print("hairpinning disabled")
  end

  local mirror = false
  if mirror_id then
  conf.ipv4_interface.mirror = true
  conf.ipv6_interface.mirror = true
  config.app(c, "Mirror", tap.Tap, mirror_id)
  config.app(c, "Sink", basic_apps.Sink)
  config.app(c, "Join", basic_apps.Join)
  config.link(c, "Join.out -> Mirror.input")
  config.link(c, "Mirror.output -> Sink.input")
  config.link(c, "nh_fwd4.mirror -> Join.in4")
  config.link(c, "nh_fwd6.mirror -> Join.in6")
  print(string.format("mirror port %s found", mirror_id))
  end

  if conf.ipv6_interface.fragmentation then
    print("IPv6 fragmentation and reassembly enabled")
    config.app(c, "reassemblerv6", ipv6_apps.Reassembler, {})
    config.link(c, v6_output .. " -> reassemblerv6.input")
    v6_output = "reassemblerv6.output"
    config.app(c, "fragmenterv6", ipv6_apps.Fragmenter, { mtu = conf.ipv6_interface.mtu })
    config.link(c, "fragmenterv6.output -> " .. v6_input)
    v6_input  = "fragmenterv6.input"
  else
    print("IPv6 fragmentation and reassembly disabled")
  end

  if conf.ipv6_interface.ipv6_ingress_filter then
    print(string.format("IPv6 ingress filter: %s", conf.ipv6_interface.ipv6_ingress_filter))
    config.app(c, "ingress_filterv6", PcapFilter, { filter = conf.ipv6_interface.ipv6_ingress_filter })
    config.link(c, v6_output .. " -> ingress_filterv6.input")
    v6_output = "ingress_filterv6.output"
  end

  if conf.ipv6_interface.ipv6_egress_filter then
    print(string.format("IPv6 egress filter: %s", conf.ipv6_interface.ipv6_egress_filter))
    config.app(c, "egress_filterv6", PcapFilter, { filter = conf.ipv6_interface.ipv6_egress_filter })
    config.link(c, "egress_filterv6.output -> " .. v6_input)
    v6_input = "egress_filterv6.input"
  end

  if conf.ipv4_interface.fragmentation then
    print("IPv4 fragmentation and reassembly enabled")
    config.app(c, "reassemblerv4", ipv4_apps.Reassembler, {})
    config.link(c, v4_output .. " -> reassemblerv4.input")
    v4_output = "reassemblerv4.output"
    config.app(c, "fragmenterv4", ipv4_apps.Fragmenter, { mtu = conf.ipv4_interface.mtu })
    config.link(c, "fragmenterv4.output -> " .. v4_input)
    v4_input  = "fragmenterv4.input"
  else
    print("IPv4 fragmentation and reassembly disabled")
  end

  if conf.ipv4_interface.ipv4_ingress_filter then
    print(string.format("IPv4 ingress filter: %s", conf.ipv4_interface.ipv4_ingress_filter))
    config.app(c, "ingress_filterv4", PcapFilter, { filter = conf.ipv4_interface.ipv4_ingress_filter })
    config.link(c, v4_output .. " -> ingress_filterv4.input")
    v4_output = "ingress_filterv4.output"
  end

  if conf.ipv4_interface.ipv4_egress_filter then
    print(string.format("IPv4 egress filter: %s", conf.ipv4_interface.ipv4_egress_filter))
    config.app(c, "egress_filterv4", PcapFilter, { filter = conf.ipv4_interface.ipv4_egress_filter })
    config.link(c, "egress_filterv4.output -> " .. v4_input)
    v4_input = "egress_filterv4.input"
  end

  if sock_path then
    config.app(c, virt_idv6, VhostUser, {socket_path=sock_path:format(conf.ipv6_interface.id)})
    config.app(c, virt_idv4, VhostUser, {socket_path=sock_path:format(conf.ipv4_interface.id)})
  else
    config.app(c, virt_idv6, basic_apps.Sink)
    config.app(c, virt_idv4, basic_apps.Sink)
    print("running without vMX! (no vHostUser sock_path set)")
  end

  if conf.preloaded_binding_table then
    print("lwaftr service enabled")
    config.app(c, "nh_fwd6", nh_fwd.nh_fwd6, conf.ipv6_interface)
    config.link(c, v6_output .. " -> nh_fwd6.wire")
    config.link(c, "nh_fwd6.wire -> " .. v6_input)

    config.app(c, "nh_fwd4", nh_fwd.nh_fwd4, conf.ipv4_interface)
    config.link(c, v4_output .. " -> nh_fwd4.wire")
    config.link(c, "nh_fwd4.wire -> " .. v4_input)

    config.link(c, virt_idv6 .. ".tx -> nh_fwd6.vmx")
    config.link(c, "nh_fwd6.vmx -> " .. virt_idv6  .. ".rx")
    config.link(c, virt_idv4 .. ".tx -> nh_fwd4.vmx")
    config.link(c, "nh_fwd4.vmx -> " .. virt_idv4  .. ".rx")

    config.app(c, "lwaftr", lwaftr.LwAftr, lwconf)
    config.link(c, "nh_fwd6.service -> lwaftr.v6")
    config.link(c, "lwaftr.v6 -> nh_fwd6.service")
    config.link(c, "nh_fwd4.service -> lwaftr.v4")
    config.link(c, "lwaftr.v4 -> nh_fwd4.service")
  else
    print("lwaftr service disabled (either empty binding_table or v6 or v4 interface config missing)")
    config.link(c, v6_output .. " -> " .. virt_idv6 .. ".rx" )
    config.link(c, virt_idv6 .. ".tx -> " .. v6_input)
    config.link(c, v4_output .. " -> " .. virt_idv4 .. ".rx" )
    config.link(c, virt_idv4 .. ".tx -> " .. v4_input)
  end

end

