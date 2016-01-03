module(..., package.seeall)

local S          = require("syscall")
local lib        = require("core.lib")
local lwaftr_conf       = require("apps.lwaftr.conf")
local pci = require("lib.hardware.pci")
local VhostUser = require("apps.vhost.vhost_user").VhostUser
local nh_fwd = require("apps.juniper.nh_fwd").nh_fwd
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
   local opts = { verbosity = 0 }
   local handlers = {}
   function handlers.v () opts.verbosity = opts.verbosity + 1 end
   function handlers.D (arg)
      opts.duration = assert(tonumber(arg), "duration must be a number")
   end
   function handlers.c(arg)
     conf_file = arg
     if not arg then
       fatal("Argument '--conf' was not set")
     end
     if not file_exists(conf_file) then
       fatal(("Couldn't locate configuration file at %s"):format(conf_file))
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
   lib.dogetopt(args, handlers, "c:s:e:f:g:i:j:k:vD:h",
      { ["conf"] = "c", ["sock"] = "s",
        ["v1id"] = "e", ["v1pci"] = "f", ["v1mac"] = "g",
        ["v2id"] = "i", ["v2pci"] = "j", ["v2mac"] = "k",
        verbose = "v", duration = "D", help = "h" })
   return opts, conf_file, v1id, v1pci, v1mac, v2id, v2pci, v2mac, sock_path
end

function run(args)
   local opts, conf_file, v1id, v1pci, v1mac, v2id, v2pci, v2mac, sock_path = parse_args(args)
   if not file_exists(conf_file) then
     fatal(("conf file %s is missing. Use --conf <config-file>"):format(conf_file))
   end
   local conf = lib.load_conf(conf_file)
   if not file_exists(conf.lwaftr) then
     fatal(("lwaftr conf file %s is missing"):format(conf.lwaftr))
   end

   local c = config.new()

   if conf.ipv6_interface then
     local si = conf.ipv6_interface
     local vmdq = true
     local vlan = si.vlan and tonumber(si.vlan)
     si.mac_address = v1mac
     config.app(c, "nh_fwd1", nh_fwd, conf.ipv6_interface)
     local VM = v1id
     if VM then
       config.app(c, VM, VhostUser, {socket_path=sock_path:format(v1id)})
       config.link(c, VM .. ".tx -> nh_fwd1.vmx")
       config.link(c, "nh_fwd1.vmx -> " ..VM .. ".rx")
     end
     if v1pci ~= "0000:00:00.0" then
       local device_info = pci.device_info(v1pci)
       if not device_info then 
         fatal(("Couldn't find device information for PCI address '%s'"):format(v1pci))
       end
       config.app(c, "v6nic", require(device_info.driver).driver,
       {pciaddr = v1pci, vmdq = vmdq, vlan = vlan, macaddr = v1mac})
       config.link(c, "v6nic.tx -> nh_fwd1.wire")
       config.link(c, "nh_fwd1.wire -> v6nic.rx")
     end
   end

   if conf.ipv4_interface then
     local si = conf.ipv4_interface
     local vlan = si.vlan and tonumber(si.vlan)
     local vmdq = true
     si.mac_address = v2mac
     config.app(c, "nh_fwd2", nh_fwd, conf.ipv4_interface)
     local VM = v2id
     if VM then
       config.app(c, VM, VhostUser, {socket_path=sock_path:format(v2id)})
       config.link(c, VM .. ".tx -> nh_fwd2.vmx")
       config.link(c, "nh_fwd2.vmx -> " ..VM .. ".rx")
     end
     if v2pci ~= "0000:00:00.0" then
       local device_info = pci.device_info(v2pci)
       if not device_info then 
         fatal(("Couldn't find device information for PCI address '%s'"):format(v2pci))
       end
       config.app(c, "v4nic", require(device_info.driver).driver,
       {pciaddr = v2pci, vmdq = vmdq, vlan = vlan, macaddr = v2mac})
       config.link(c, "v4nic.tx -> nh_fwd2.wire")
       config.link(c, "nh_fwd2.wire -> v4nic.rx")
     end
   end

   local lwconf = lwaftr_conf.load_lwaftr_config(conf.lwaftr)
   if not file_exists(lwconf.address_map) then
     fatal(("Couldn't locate address_map file at %s"):format(lwconf.address_map))
   end
   if not file_exists(lwconf.binding_table) then
     fatal(("Couldn't locate binding_table file at %s"):format(lwconf.binding_table))
   end

   config.app(c, "lwaftr", lwaftr, lwconf)
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
