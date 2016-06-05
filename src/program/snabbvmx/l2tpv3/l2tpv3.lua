module(..., package.seeall)

local engine      = require("core.app")
local main        = require("core.main")
local timer       = require("core.timer")
local lib         = require("core.lib")
local S           = require("syscall")
local config      = require("core.config")
local config      = require("core.config")
local pci         = require("lib.hardware.pci")
local Tap         = require("apps.tap.tap").Tap
local VhostUser   = require("apps.vhost.vhost_user").VhostUser
local pcap        = require("apps.pcap.pcap")
local lib         = require("core.lib")
local l2tpv3      = require("apps.l2tpv3.l2tpv3").SimpleKeyedTunnel

local usage = require("program.snabbvmx.l2tpv3.README_inc")

local long_opts = {
   conf     = "c",   -- configuration file 
   id       = "i",   -- port_id for virtio socket 
   sock     = "s",   -- socket path for virtio interface
   mac      = "m",   -- Ethernet
   tap      = "t",   -- TAP interface name
   pci      = "p",   -- PCI address
   read     = "r",   -- read pcap file as input
   write    = "w",   -- write pcap file for output
   single   = "S",   -- single stick mode (IPv6 and trunk packets over pci/tap port)
   duration = "D",   -- Duration in seconds
   verbose  = "V",   -- display stats
   help     = "h" 
}

local function file_exists(path)
   local stat = S.stat(path)
   return stat and stat.isreg
end

local function dir_exists(path)
  local stat = S.stat(path)
  return stat and stat.isdir
end

local function nic_exists(pci_addr)
  local devices="/sys/bus/pci/devices"
  return dir_exists(("%s/%s"):format(devices, pci_addr)) or
  dir_exists(("%s/0000:%s"):format(devices, pci_addr))
end

function run (args)
   local opt = {}
   local duration
   local conf = {}
   local c = config.new()

   function opt.D (arg)
      duration = assert(tonumber(arg), "duration is not a number!")
   end

   local verbose
   function opt.V (arg)
      verbose = true
   end

   function opt.h (arg)
      print(usage)
      main.exit(0)
   end

   local conf_file
   function opt.c (arg)
      if file_exists(arg) then
         conf_file = arg
         conf_f = assert(loadfile(conf_file))
         conf = conf_f()
      else
         print(string.format("configuration file %s not found",conf_file))
      end
   end

   local id
   function opt.i (arg)
      id = arg
   end

   local sock_path
   function opt.s (arg)
      sock_path = arg
   end

   local target

   local mac_address
   function opt.m (arg)
      mac_address = arg
   end

   local tap_interface
   function opt.t (arg)
      tap_interface = arg
      target = tap_interface
   end

   local pci_addr
   function opt.p (arg)
      pci_addr = arg
      target = pci_addr
   end

   local pcap_read
   function opt.r (arg)
      pcap_read = arg
      if not file_exists(pcap_read) then
         print(string.format("pcap file %s doesn't exist", pcap_read))
         main.exit(1)
      end
      target = pcap_read
   end

   local pcap_write
   function opt.w (arg)
      pcap_write = arg
      target = pcap_write
   end

   function opt.S (arg)
      conf.single_stick = true
   end

   local mac_address
   function opt.m (arg)
      mac_address = arg
   end

   args = lib.dogetopt(args, opt, "c:i:s:t:p:r:m:w:m:SD:hV", long_opts)

   if not target then
      print("either --pci or --tap is required")
      main.exit(1)
   end

   if not mac_address then
      print("--mac address is required")
      main.exit(1)
   end

   local input, output

   if tap_interface then
      if dir_exists(("/sys/devices/virtual/net/%s"):format(tap_interface)) then
         print(string.format("tap interface %s found", tap_interface))
         config.app(c, "tap", Tap, tap_interface)
         input, output = "tap.input", "tap.output"
      else
         print(string.format("tap interface %s doesn't exist", tap_interface))
         main.exit(1)
      end
   elseif pci_addr then
      local device_info = pci.device_info(pci_addr)
      if device_info then
         config.app(c, "nic", require(device_info.driver).driver,
         {pciaddr = pci_addr, vmdq = false, mtu = 9500})
         input, output = "nic.rx", "nic.tx"
      else
         print(string.format("Couldn't find device info for PCI or tap device %s", pci_addr))
         main.exit(1)
      end
   end

   if pcap_read and pcap_write then
      config.app(c, "read", pcap.PcapReader, pcap_read)
      output = "read.output"
      config.app(c, "write", pcap.PcapWriter, pcap_write)
      input = "write.input"
   end

   if conf.tunnels and type(conf.tunnels) == "table" then
      if not conf.ipv6_address then
         print("ipv6_address (local tunnel endpoint) missing from config")
         main.exit(1)
      end
      config.app(c, "l2tpv3", l2tpv3, { id = id, tunnels = conf.tunnels, ipv6_address = conf.ipv6_address, mac_address = mac_address, single_stick = conf.single_stick })
      config.link(c, output .. " -> l2tpv3.ipv6")
      config.link(c, "l2tpv3.ipv6 -> " .. input)
      input, output = "l2tpv3.trunk", "l2tpv3.trunk"
   else
      print("no tunnels found. Running in passthru mode")
   end

   if sock_path then
      config.app(c, id, VhostUser, {socket_path=sock_path:format(id)})
      config.link(c, id .. ".tx -> " .. input)
      config.link(c, output .. " -> " .. id  .. ".rx")
   else
      print("No socket path (--sock) given, using loopback mode without virtio")
      config.link(c, input .. " -> " .. output)
      config.link(c, output .. " -> " .. input)
   end

   engine.busywait =true
   engine.configure(c)

   if verbose then
      local fn = function ()
         print("Transmissions (last second):")
         engine.report_apps()
      end
      local t = timer.new("report", fn, 1e9, 'repeating')
      timer.activate(t)
   end

   if duration then engine.main({duration=duration})
   else             engine.main() end
end
