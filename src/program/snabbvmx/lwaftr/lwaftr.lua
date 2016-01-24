module(..., package.seeall)

local S          = require("syscall")
local lib        = require("core.lib")
local lwaftr_conf       = require("apps.lwaftr.conf")
local pci = require("lib.hardware.pci")
local VhostUser = require("apps.vhost.vhost_user").VhostUser
local nh_fwd = require("apps.juniper.nh_fwd").nh_fwd
local tap = require("apps.tap.tap").Tap
local ipv4_apps  = require("apps.lwaftr.ipv4_apps")
local ipv6_apps  = require("apps.lwaftr.ipv6_apps")
local lwaftr = require("apps.lwaftr.lwaftr").LwAftr

local function show_usage(exit_code)
   print(require("program.snabbvmx.lwaftr.README_inc"))
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

function parse_args(args)
   if #args == 0 then show_usage(1) end
   local conf_file, sock_path, v1id, v1pci, v1mac, v2id, v2pci, v2mac
   local opts = {}
   local handlers = {}
   function handlers.D (arg)
      opts.duration = assert(tonumber(arg), "duration must be a number")
   end
   function handlers.c(arg)
     conf_file = arg
     if not arg then
       fatal("Argument '--conf' was not set")
     end
   end
   function handlers.e(arg)
      v1id = arg
      if not arg then
         fatal("Argument '--v1id' was not set")
      end
   end
   function handlers.f(arg)
      v1pci = arg
      if not arg then
         fatal("Argument '--v1pci' was not set")
      end
   end
   function handlers.g(arg)
      v1mac = arg
      if not arg then
         fatal("Argument '--v1mac' was not set")
      end
   end
   function handlers.i(arg)
      v2id = arg
      if not arg then
         fatal("Argument '--v2id' was not set")
      end
   end
   function handlers.j(arg)
      v2pci = arg
      if not arg then
         fatal("Argument '--v2pci' was not set")
      end
   end
   function handlers.k(arg)
      v2mac = arg
      if not arg then
         fatal("Argument '--v2mac' was not set")
      end
   end
   function handlers.s(arg)
      sock_path = arg
      if not arg then
         fatal("Argument '--sock' was not set")
      end
   end
   function handlers.h() show_usage(0) end
   lib.dogetopt(args, handlers, "c:s:e:f:g:i:j:k:D:h",
      { ["conf"] = "c", ["sock"] = "s",
        ["v1id"] = "e", ["v1pci"] = "f", ["v1mac"] = "g",
        ["v2id"] = "i", ["v2pci"] = "j", ["v2mac"] = "k",
        duration = "D", help = "h" })
   return opts, conf_file, v1id, v1pci, v1mac, v2id, v2pci, v2mac, sock_path
end

local function config_interface(c, id, pciaddr, mac, nic_name, nh_fwd_name, interface, sock_path)

     assert(type(interface) == 'table')

     local vlan = interface.vlan and tonumber(interface.vlan)
     interface.mac_address = mac
     config.app(c, nh_fwd_name, nh_fwd, interface)
     if id then
       config.app(c, id, VhostUser, {socket_path=sock_path:format(id)})
       config.link(c, id .. ".tx -> " .. nh_fwd_name .. ".vmx")
       config.link(c, nh_fwd_name .. ".vmx -> " .. id  .. ".rx")
     end
     if pciaddr ~= "0000:00:00.0" then
       if string.find(pciaddr,"tap") then
         config.app(c, nic_name, tap, pciaddr)
         config.link(c, nic_name .. "output -> " .. nh_fwd_name .. ".wire")
         config.link(c, nh_fwd_name .. ".wire -> " .. nic_name .. ".input")
       else
         local device_info = pci.device_info(pciaddr)
         if not device_info then 
           fatal(("Couldn't find device information for PCI address '%s'"):format(pciaddr))
         end
         config.app(c, nic_name, require(device_info.driver).driver,
         {pciaddr = pciaddr, vmdq = true, vlan = vlan, macaddr = mac})
         config.link(c, nic_name .. ".tx -> " .. nh_fwd_name .. ".wire")
         config.link(c, nh_fwd_name .. ".wire -> " .. nic_name .. ".rx")
       end
     end

end

function run(args)
   local opts, conf_file, v1id, v1pci, v1mac, v2id, v2pci, v2mac, sock_path = parse_args(args)
   local conf = {}

   if not file_exists(conf_file) then
     fatal(("config file %s not found"):format(conf_file))
   end

   conf = lib.load_conf(conf_file)
   if not file_exists(conf.lwaftr) then
       fatal(("lwaftr conf file %s is missing"):format(conf.lwaftr))
   end

   local c = config.new()

   if (conf.ipv6_interface and conf.ipv4_interface) then
     config_interface(c, v1id, v1pci, v1mac, 'v6nic', 'nh_fwd1', conf.ipv6_interface, sock_path)
     config_interface(c, v2id, v2pci, v2mac, 'v4nic', 'nh_fwd2', conf.ipv4_interface, sock_path)
   else
     fatal(("need ipv4_interface and ipv6_interface group in %s"):format(conf_file))
   end

   if conf.lwaftr then
     local lwconf = lwaftr_conf.load_lwaftr_config(conf.lwaftr)
     if not file_exists(lwconf.binding_table) then
       fatal(("Couldn't locate binding_table file at %s"):format(lwconf.binding_table))
     end

     config.app(c, "lwaftr", lwaftr, lwconf)

     local v6_fragmentation = conf.ipv6_interface.fragmentation 
     if false ~= v6_fragmentation then
       v6_fragmentation = true
     end
     local v4_fragmentation = conf.ipv4_interface.fragmentation
     if false ~= v4_fragmentation then
       v4_fragmentation = true
     end
     local v6_mtu = lwconf.ipv6_mtu or 1500
     local v4_mtu = lwconf.ipv4_mtu or 1460

     if v6_fragmentation then
       print("Enable IPv6 fragmentation and reassembly")
       config.app(c, "reav6", ipv6_apps.Reassembler, {}) 
       config.app(c, "fragv6", ipv6_apps.Fragmenter, { mtu=v6_mtu })
       config.link(c, "nh_fwd1.service -> reav6.input")
       config.link(c, "reav6.output -> lwaftr.v6")
       config.link(c, "lwaftr.v6 -> fragv6.input")
       config.link(c, "fragv6.output -> nh_fwd1.service")
     else
       print("IPv6 fragmentation and reassembly DISABLED")
       config.link(c, 'nh_fwd1.service -> lwaftr.v6')
       config.link(c, 'lwaftr.v6 -> nh_fwd1.service')
     end

     if v4_fragmentation then
       print("Enable IPv4 fragmentation and reassembly")
       config.app(c, "reav4", ipv4_apps.Reassembler, {}) 
       config.app(c, "fragv4", ipv4_apps.Fragmenter, { mtu=v4_mtu })
       config.link(c, "nh_fwd2.service -> reav4.input")
       config.link(c, "reav4.output -> lwaftr.v4")
       config.link(c, "lwaftr.v4 -> fragv4.input")
       config.link(c, "fragv4.output -> nh_fwd2.service")
     else
       print("IPv4 fragmentation and reassembly DISABLED")
       config.link(c, 'nh_fwd2.service -> lwaftr.v4')
       config.link(c, 'lwaftr.v4 -> nh_fwd2.service')
     end

   else
     fatal(("need lwaftr group in %s"):format(conf_file))
   end

   engine.configure(c)

   if opts.duration then
      engine.main({duration=opts.duration, report={showlinks=true}})
   else
      engine.main({report={showlinks=true}})
   end
end
