module(..., package.seeall)

local VhostUser = require("apps.vhost.vhost_user").VhostUser
local basic_apps = require("apps.basic.basic_apps")
local config = require("core.config")
local ethernet = require("lib.protocol.ethernet")
local lib = require("core.lib")
local vhag = require("apps.vhag.vhag")
--local vhcounter = require("apps.vhag.vhounter")
local lwutil = require("apps.lwaftr.lwutil")
local constants = require("apps.lwaftr.constants")
local pci = require("lib.hardware.pci")
local raw = require("apps.socket.raw")
local tap = require("apps.tap.tap")
local pcap = require("apps.pcap.pcap")

local fatal, file_exists = lwutil.fatal, lwutil.file_exists
local dir_exists, nic_exists = lwutil.dir_exists, lwutil.nic_exists
local yesno = lib.yesno

local function net_exists (pci_addr)
   local devices="/sys/class/net"
   return dir_exists(("%s/%s"):format(devices, pci_addr))
end

local function nic_exists(pci_addr)
  local devices="/sys/bus/pci/devices"
  return dir_exists(("%s/%s"):format(devices, pci_addr)) or
  dir_exists(("%s/0000:%s"):format(devices, pci_addr))
end

local function load_driver (pciaddr)
   local device_info = pci.device_info(pciaddr)
   return require(device_info.driver).driver
end

local function load_interface(c, id, interface)
  assert(type(interface) == 'table')
  local vlan = interface.vlan and tonumber(interface.vlan)
  local chain_input, chain_output

  print(("interface=%s mac=%s"):format(interface.interface, interface.mac_address))
  
  if nic_exists(interface.interface) then
    local device_info = pci.device_info(interface.interface)
    -- check first for physical interface specified via pci address
    if device_info then
      config.app(c, id, require(device_info.driver).driver, {
        pciaddr = interface.interface, 
        vmdq = interface.vlan and true,
        vlan = interface.vlan, 
        macaddr = ethernet:ntop(interface.mac_address),
        mtu = conf.mtu
      })

      chain_input, chain_output = id .. ".rx", id .. ".tx"
    end
  else
    -- check for linux interface, e.g. eth0
    if net_exists(interface.interface) then
      if interface.vlan then
        print(("WARNING: VLAN not supported over %s. %s vlan %d"):format(interface.interface, id, interface.vlan))
      end
      config.app(c, id, raw.RawSocket, interface.interface)
      chain_input, chain_output = id .. ".rx", id .. ".tx"
    elseif file_exists(interface.interface) then
      print(("Reading from PCAP file %s"):format(interface.interface))
      local pcap_output_file = string.gsub(interface.interface, ".pcap", ".out.pcap")
      config.app(c, id .. "_in", pcap.PcapReader, interface.interface)
      config.app(c, id .. "_out", pcap.PcapWriter, pcap_output_file)
      chain_input, chain_output = id .. "_out.input", id .. "_in.output"
    else
      config.app(c, id, VhostUser, { socket_path = interface.interface })
      chain_input, chain_output = id .. ".rx", id .. ".tx"
    end
  end
  return chain_input, chain_output
end

function vhag_app(c, conf)
  assert(type(conf) == 'table')

  --   local counters = vhcounter.init_counters()

  local access_id = "ac_" .. conf.id
  local trunk_id = "tr_" .. conf.id

  local chain_input, chain_output

  chain_input, chain_output = load_interface(c, access_id, conf.access)

  print(("id=%s ipv4=%s"):format(conf.id, conf.ipv4_address))
  config.app(c, "vhag", vhag.Vhag, conf)
  config.link(c, chain_output .. " -> vhag.access")
  config.link(c, "vhag.access -> " .. chain_input)

  if conf.trunk then
    local trunk_input, trunk_output = load_interface(c, trunk_id, conf.trunk)
    config.link(c, "vhag.trunk -> " .. trunk_input)
    config.link(c, trunk_output .. " -> vhag.trunk")
  else
    print("No trunk given, using loopback mode")
    config.link(c, "vhag.trunk -> vhag.trunk")
  end

end

function load_check(c, conf_filename, inv4_pcap, inv6_pcap, outv4_pcap, outv6_pcap)
  local conf, lwconf = load_conf(conf_filename)

  config.app(c, "capturev4", pcap.PcapReader, inv4_pcap)
  config.app(c, "capturev6", pcap.PcapReader, inv6_pcap)
  config.app(c, "output_filev4", pcap.PcapWriter, outv4_pcap)
  config.app(c, "output_filev6", pcap.PcapWriter, outv6_pcap)
  if conf.vlan_tagging then
    config.app(c, "untagv4", vlan.Untagger, { tag=conf.v4_vlan_tag })
    config.app(c, "untagv6", vlan.Untagger, { tag=conf.v6_vlan_tag })
    config.app(c, "tagv4", vlan.Tagger, { tag=conf.v4_vlan_tag })
    config.app(c, "tagv6", vlan.Tagger, { tag=conf.v6_vlan_tag })
  end

  local sources = { "capturev4.output", "capturev6.output" }
  local sinks = { "output_filev4.input", "output_filev6.input" }

  if conf.vlan_tagging then
    sources = { "untagv4.output", "untagv6.output" }
    sinks = { "tagv4.input", "tagv6.input" }

    config.link(c, "capturev4.output -> untagv4.input")
    config.link(c, "capturev6.output -> untagv6.input")
    config.link(c, "tagv4.output -> output_filev4.input")
    config.link(c, "tagv6.output -> output_filev6.input")
  end

  vhag_app_check(c, conf, lwconf, sources, sinks)
end
