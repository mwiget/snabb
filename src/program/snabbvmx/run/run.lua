module(..., package.seeall)

local S          = require("syscall")
local lib        = require("core.lib")
-- local ethernet   = require("lib.protocol.ethernet")
-- local Intel82599 = require("apps.intel.intel_app").Intel82599
-- local basic_apps = require("apps.basic.basic_apps")
-- local bt         = require("apps.lwaftr.binding_table")
-- local conf       = require("apps.lwaftr.conf")
-- local lwaftr     = require("apps.lwaftr.lwaftr")
local pci = require("lib.hardware.pci")
local VhostUser = require("apps.vhost.vhost_user").VhostUser
-- local PcapFilter = require("apps.packet_filter.pcap_filter").PcapFilter
-- local RateLimiter = require("apps.rate_limiter.rate_limiter").RateLimiter
local nh_fwd = require("apps.juniper.nh_fwd").nh_fwd
local conf   = require("apps.juniper.ssh_conf")
local lwaftr = require("apps.lwaftr.lwaftr").LwAftr

local function show_usage(exit_code)
   print(require("program.snabbvmx.run.README_inc"))
   if exit_code then main.exit(exit_code) end
end

local function fatal(msg)
   show_usage()
   print(msg)
   main.exit(1)
end

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

function parse_args(args)
   if #args == 0 then show_usage(1) end
   local v4_port, v6_port, v4_pci, v6_pci, v4_mac, v6_mac, sock_path, ip, user, identity
   local opts = { verbosity = 0 }
   local handlers = {}
   function handlers.v () opts.verbosity = opts.verbosity + 1 end
   function handlers.D (arg)
      opts.duration = assert(tonumber(arg), "duration must be a number")
   end
   function handlers.p(arg)
      v6_port = arg
      if not arg then
         fatal("Argument '--v6-port' was not set")
      end
   end
   function handlers.q(arg)
      v4_port = arg
      if not arg then
         fatal("Argument '--v4-port' was not set")
      end
   end
   function handlers.n(arg)
      v4_pci = arg
      if not arg then
         fatal("Argument '--v4-pci' was not set")
      end
      if not nic_exists(v4_pci) then
         fatal(("Couldn't locate NIC with PCI address '%s'"):format(v4_pci))
      end
   end
   function handlers.m(arg)
      v6_pci = arg
      if not v6_pci then
         fatal("Argument '--v6-pci' was not set")
      end
      if not nic_exists(v6_pci) then
         fatal(("Couldn't locate NIC with PCI address '%s'"):format(v6_pci))
      end
   end
   function handlers.s(arg)
      sock_path = arg
      if not arg then
         fatal("Argument '--sock' was not set")
      end
   end
   function handlers.a(arg)
      v4_mac = arg
      if not arg then
         fatal("Argument '--v4-mac' was not set")
      end
   end
   function handlers.b(arg)
      v6_mac = arg
      if not arg then
         fatal("Argument '--v6-mac' was not set")
      end
   end
   function handlers.u(arg)
      user = arg
      if not arg then
         fatal("Argument '--user' was not set")
      end
   end
   function handlers.i(arg)
      ip = arg
      if not arg then
         fatal("Argument '--ip' was not set")
      end
   end
   function handlers.y(arg)
      identity = arg
      if not arg then
         fatal("Argument '--identity' was not set (netconf/ssh private key)")
      end
   end
   function handlers.h() show_usage(0) end
   lib.dogetopt(args, handlers, "n:m:q:p:a:b:u:i:y:s:vD:h",
      { ["v4-pci"] = "n", ["v6-pci"] = "m",
        ["v4-port"] = "q", ["v6-port"] = "p",
        ["v4-mac"] = "a", ["v6-mac"] = "b",
        ["user"] = "u", ["ip"] = "i", ["identity"] = "y",
        ["sock"] = "s", verbose = "v", duration = "D", help = "h" })
   return opts, v4_pci, v6_pci, v4_port, v6_port, v4_mac, v6_mac, user, ip, identity, sock_path
end

function run(args)
   local opts, v4_pci, v6_pci, v4_port, v6_port, v4_mac, v6_mac, user, ip, identity, sock_path = parse_args(args)
   local aftrconf = conf.get_aftrconf(v6_port, v4_port, ip, user, identity)
   aftrconf.ipv4_interface.mac_address = v4_mac
   aftrconf.ipv6_interface.mac_address = v6_mac
   aftrconf.ipv4_interface.port_id = v4_port
   aftrconf.ipv6_interface.port_id = v6_port

   local c = config.new()

   if aftrconf.ipv6_interface then
     local si = aftrconf.ipv6_interface
     local vlan, mac_address = si.vlan, si.mac_address
     local vmdq = true
     if not mac_address then
       fatal("mac_address is missing for ipv6_interface")
     end
     if vlan then
       vlan = tonumber(vlan)
     end
     if si.mtu then
       print(string.format("ipv6 mtu is set to %d", si.mtu))
     end
     config.app(c, "nh_fwd1", nh_fwd, aftrconf.ipv6_interface)
     local VM = si.port_id
     if VM then
       print("v6 side VM=" .. VM)
       print("socket_path=" .. sock_path:format(si.port_id))
       config.app(c, VM, VhostUser, {socket_path=sock_path:format(si.port_id)})
       config.link(c, VM .. ".tx -> nh_fwd1.vmx")
       config.link(c, "nh_fwd1.vmx -> " ..VM .. ".rx")
     end
     if v6_pci ~= "0000:00:00.0" then
       local device_info = pci.device_info(v6_pci)
       if not device_info then 
         fatal(("Couldn't find device information for PCI address '%s'"):format(v6_pci))
       end
       config.app(c, "v6nic", require(device_info.driver).driver,
       {pciaddr = v6_pci, vmdq = vmdq, vlan = vlan, macaddr = mac_address})
       config.link(c, "v6nic.tx -> nh_fwd1.wire")
       config.link(c, "nh_fwd1.wire -> v6nic.rx")
     end
   end

   if aftrconf.ipv4_interface then
     local si = aftrconf.ipv4_interface
     local vlan, mac_address = si.vlan, si.mac_address
     local vmdq = true
     if not mac_address then
       fatal("mac_address is missing for ipv4_interface")
     end
     if vlan then
       vlan = tonumber(vlan)
     end
     config.app(c, "nh_fwd2", nh_fwd, aftrconf.ipv4_interface)
     local VM = si.port_id
     if VM then
       print("v4 side VM=" .. VM)
       print("socket_path=" .. sock_path:format(si.port_id))
       config.app(c, VM, VhostUser, {socket_path=sock_path:format(si.port_id)})
       config.link(c, VM .. ".tx -> nh_fwd2.vmx")
       config.link(c, "nh_fwd2.vmx -> " ..VM .. ".rx")
     end
     if v4_pci ~= "0000:00:00.0" then
       local device_info = pci.device_info(v4_pci)
       if not device_info then 
         fatal(("Couldn't find device information for PCI address '%s'"):format(v4_pci))
       end
       config.app(c, "v4nic", require(device_info.driver).driver,
       {pciaddr = v4_pci, vmdq = vmdq, vlan = vlan, macaddr = mac_address})
       config.link(c, "v4nic.tx -> nh_fwd2.wire")
       config.link(c, "nh_fwd2.wire -> v4nic.rx")
     end
   end
   config.app(c, "lwaftr", lwaftr, aftrconf)
   config.link(c, 'nh_fwd1.lwaftr -> lwaftr.v6')
   config.link(c, 'nh_fwd2.lwaftr -> lwaftr.v4')
   config.link(c, 'lwaftr.v4 -> nh_fwd2.lwaftr')
   config.link(c, 'lwaftr.v6 -> nh_fwd1.lwaftr')

   engine.configure(c)

   if opts.verbosity >= 2 then
      local function lnicui_info()
         app.report_apps()
      end
      local t = timer.new("report", lnicui_info, 1e9, 'repeating')
      timer.activate(t)
   end

   if opts.verbosity >= 1 then
      local csv = csv_stats.CSVStatsTimer.new()
      csv:add_app('v4nic', { 'tx', 'rx' }, { tx='IPv4 RX', rx='IPv4 TX' })
      csv:add_app('v6nic', { 'tx', 'rx' }, { tx='IPv6 RX', rx='IPv6 TX' })
      csv:activate()
   end
   
   local linkreportinterval = 10

   if linkreportinterval > 0 then
     local t = timer.new("linkreport", engine.report_links, linkreportinterval*1e9, 'repeating')
     timer.activate(t)
   end

   local loadreportinterval = 1
   if loadreportinterval > 0 then
     local t = timer.new("loadreport", engine.report_load, loadreportinterval*1e9, 'repeating')
     timer.activate(t)
   end

   if opts.duration then
      engine.main({duration=opts.duration, report={showlinks=true}})
   else
      engine.main({report={showlinks=true}})
   end
end
