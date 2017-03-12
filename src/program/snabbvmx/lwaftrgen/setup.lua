module(..., package.seeall)

local V4V6 = require("apps.lwaftr.V4V6").V4V6
local VhostUser = require("apps.vhost.vhost_user").VhostUser
local basic_apps = require("apps.basic.basic_apps")
local config = require("core.config")
local ethernet = require("lib.protocol.ethernet")
local lib = require("core.lib")
local Lwaftrgen = require("program.snabbvmx.lwaftrgen.lib").Lwaftrgen
local lwutil = require("apps.lwaftr.lwutil")
local constants = require("apps.lwaftr.constants")
local nh_fwd = require("apps.lwaftr.nh_fwd")
local pci = require("lib.hardware.pci")
local raw = require("apps.socket.raw")
local tap = require("apps.tap.tap")
local conf = require("program.snabbvmx.lwaftrgen.conf")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")

local fatal, file_exists = lwutil.fatal, lwutil.file_exists
local dir_exists, nic_exists = lwutil.dir_exists, lwutil.nic_exists
local yesno = lib.yesno

local function net_exists (pci_addr)
   local devices="/sys/class/net"
   return dir_exists(("%s/%s"):format(devices, pci_addr))
end

local function subset (keys, conf)
   local ret = {}
   for k,_ in pairs(keys) do ret[k] = conf[k] end
   return ret
end

local function load_driver (pciaddr)
   local device_info = pci.device_info(pciaddr)
   return require(device_info.driver).driver
end

local function load_virt (c, nic_id, lwconf, interface)
   assert(type(interface) == 'table')
   assert(nic_exists(interface.pci), "Couldn't find NIC: "..interface.pci)
   local driver = assert(load_driver(interface.pci))

   print("Different VLAN tags: load two virtual interfaces")
   print(("%s ether %s"):format(nic_id, interface.mac_address))

   local v4_nic_name, v6_nic_name = nic_id..'_v4', nic_id..'v6'
   local v4_mtu = lwconf.ipv4_mtu + constants.ethernet_header_size
   if lwconf.vlan_tagging and lwconf.v4_vlan_tag then
     v4_mtu = v4_mtu + 4
   end
   print(("Setting %s interface MTU to %d"):format(v4_nic_name, v4_mtu))
   config.app(c, v4_nic_name, driver, {
      pciaddr = interface.pci,
      vmdq = interface.vlan and true,
      vlan = interface.vlan and interface.vlan.v4_vlan_tag,
      macaddr = ethernet:ntop(lwconf.aftr_mac_inet_side),
      mtu = v4_mtu })
   local v6_mtu = lwconf.ipv6_mtu + constants.ethernet_header_size
   if lwconf.vlan_tagging and lwconf.v6_vlan_tag then
     v6_mtu = v6_mtu + 4
   end
   print(("Setting %s interface MTU to %d"):format(v6_nic_name, v6_mtu))
   config.app(c, v6_nic_name, driver, {
      pciaddr = interface.pci,
      vmdq = interface.vlan and true,
      vlan = interface.vlan and interface.vlan.v6_vlan_tag,
      macaddr = ethernet:ntop(lwconf.aftr_mac_b4_side),
      mtu = v6_mtu})

   return v4_nic_name, v6_nic_name
end

local function load_phy (c, nic_id, interface)
   assert(type(interface) == 'table')
   local vlan = interface.vlan and tonumber(interface.vlan)
   local chain_input, chain_output

   if nic_exists(interface.pci) then
      local driver = load_driver(interface.pci)
      vlan = interface.vlan and tonumber(interface.vlan)
      print(("%s network ether %s mtu %d"):format(nic_id, interface.mac_address, interface.mtu))
      if vlan then
         print(("%s vlan %d"):format(nic_id, vlan))
      end
      config.app(c, nic_id, driver, {
         pciaddr = interface.pci,
         vmdq = true,
         vlan = vlan,
         macaddr = interface.mac_address,
         mtu = interface.mtu})
      chain_input, chain_output = nic_id .. ".rx", nic_id .. ".tx"
   elseif net_exists(interface.pci) then
      print(("%s network interface %s mtu %d"):format(nic_id, interface.pci, interface.mtu))
      if vlan then
         print(("WARNING: VLAN not supported over %s. %s vlan %d"):format(interface.pci, nic_id, vlan))
      end
      config.app(c, nic_id, raw.RawSocket, interface.pci)
      chain_input, chain_output = nic_id .. ".rx", nic_id .. ".tx"
   else
      print(("Couldn't find device info for PCI address '%s'"):format(interface.pci))
      if not interface.mirror_id then
         fatal("Neither PCI nor tap interface given")
      end
      print(("Using tap interface '%s' instead"):format(interface.mirror_id))
      config.app(c, nic_id, tap.Tap, interface.mirror_id)
      print(("Running VM via tap interface '%s'"):format(interface.mirror_id))
      interface.mirror_id = nil   -- Hack to avoid opening again as mirror port.
      print(("SUCCESS %s"):format(chain_input))
      chain_input, chain_output = nic_id .. ".input", nic_id .. ".output"
   end
   return chain_input, chain_output
end

local function requires_splitter (lwconf)
   if not lwconf.vlan_tagging then return true end
   return lwconf.v4_vlan_tag == lwconf.v6_vlan_tag
end

function lwaftrgen_app(c, conf, lwconf, sock_path)
   assert(type(conf) == 'table')
   assert(type(lwconf) == 'table')

   local virt_id = "vm_" .. conf.interface.id
   local phy_id = "nic_" .. conf.interface.id

   local chain_input, chain_output
   local v4_input, v4_output, v6_input, v6_output

   local use_splitter = requires_splitter(lwconf)
   if not use_splitter then
     print("no splitter")
      local v4, v6 = load_virt(c, phy_id, lwconf, conf.interface)
      v4_output, v6_output = v4..".tx", v6..".tx"
      v4_input, v6_input   = v4..".rx", v6..".rx"
   else
      chain_input, chain_output = load_phy(c, phy_id, conf.interface)
     print(("use splitter chain_input=%s chain_output=%s"):format(chain_input,chain_output))
     print(("interface %s mac_address=%s"):format(conf.interface.id, conf.interface.mac_address))
   end

   if conf.ipv4_interface or conf.ipv6_interface then
      if use_splitter then
         config.app(c, "nic_v4v6", V4V6, { description = "nic_v4v6" })
         config.link(c, chain_output .. " -> nic_v4v6.input")
         config.link(c, "nic_v4v6.output -> " .. chain_input)

         v4_output, v6_output = "nic_v4v6.v4", "nic_v4v6.v6"
         v4_input, v6_input   = "nic_v4v6.v4", "nic_v4v6.v6"
      end
   end

   if conf.ipv6_interface then
      conf.ipv6_interface.mac_address = conf.interface.mac_address
   end

   if conf.ipv4_interface then
      conf.ipv4_interface.mac_address = conf.interface.mac_address
   end

   if conf.ipv4_interface and conf.ipv6_interface then
      print("Packetblaster lwAFTR service: enabled")
      config.app(c, "nh_fwd6", nh_fwd.nh_fwd6,
                 subset(nh_fwd.nh_fwd6.config, conf.ipv6_interface))
      config.link(c, v6_output .. " -> nh_fwd6.wire")
      config.link(c, "nh_fwd6.wire -> " .. v6_input)
      v6_input, v6_output = "nh_fwd6.vm", "nh_fwd6.vm"

      config.app(c, "nh_fwd4", nh_fwd.nh_fwd4,
                 subset(nh_fwd.nh_fwd4.config, conf.ipv4_interface))
      config.link(c, v4_output .. " -> nh_fwd4.wire")
      config.link(c, "nh_fwd4.wire -> " .. v4_input)
      v4_input, v4_output = "nh_fwd4.vm", "nh_fwd4.vm"

      sizes = {}
      for size in string.gmatch(lwconf.sizes,"([%d%.%+%-]+),?") do
        local s = tonumber(size)
        sizes[#sizes+1] = s
      end

      config.app(c, "lwaftrgen", Lwaftrgen, {
        sizes = sizes, count = lwconf.count, aftr_ipv6 = ipv6:ntop(lwconf.aftr_ipv6), 
        rate = lwconf.rate,
        src_mac = conf.interface.mac_address, dst_mac = "02:55:55:55:55:55", vlan = lwconf.vlan,
        b4_ipv6 = ipv6:ntop(lwconf.b4_ipv6), b4_ipv4 = ipv4:ntop(lwconf.b4_ipv4), 
        b4_port = lwconf.b4_port, public_ipv4 = ipv4:ntop(lwconf.public_ipv4), single_pass = false,
        ipv4_only = false, ipv6_only = false })

      config.link(c, "nh_fwd6.service -> lwaftrgen.v6")
      config.link(c, "lwaftrgen.v6 -> nh_fwd6.service")
      config.link(c, "nh_fwd4.service -> lwaftrgen.v4")
      config.link(c, "lwaftrgen.v4 -> nh_fwd4.service")

   else
      io.write("lwAFTR service: disabled ")
      print("(either empty binding_table or v6 or v4 interface config missing)")
   end

   if conf.ipv4_interface or conf.ipv6_interface then
      config.app(c, "vm_v4v6", V4V6, { description = "vm_v4v6",
                                       mirror = false })
      config.link(c, v6_output .. " -> vm_v4v6.v6")
      config.link(c, "vm_v4v6.v6 -> " .. v6_input)
      config.link(c, v4_output .. " -> vm_v4v6.v4")
      config.link(c, "vm_v4v6.v4 -> " .. v4_input)
      chain_input, chain_output = "vm_v4v6.input", "vm_v4v6.output"
   end

   if sock_path then
      local socket_path = sock_path:format(conf.interface.id)
      config.app(c, virt_id, VhostUser, { socket_path = socket_path })
      config.link(c, virt_id .. ".tx -> " .. chain_input)
      config.link(c, chain_output .. " -> " .. virt_id  .. ".rx")
   else
      config.app(c, "DummyVhost", basic_apps.Sink)
      config.link(c, "DummyVhost" .. ".tx -> " .. chain_input)
      config.link(c, chain_output .. " -> " .. "DummyVhost"  .. ".rx")
      print("Running without VM (no vHostUser sock_path set)")
   end
end

local function load_conf (conf_filename)
   local function load_lwaftr_config (conf, conf_filename)
      local filename = conf.lwaftrgen
      if not file_exists(filename) then
         filename = lib.dirname(conf_filename).."/"..filename
      end
      return conf.load_lwaftrgen_config(filename)
   end
   local conf = dofile(conf_filename)
   return conf, load_lwaftr_config(conf, conf_filename)
end

