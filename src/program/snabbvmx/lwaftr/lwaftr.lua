module(..., package.seeall)

local S          = require("syscall")
local config     = require("core.config")
local lib        = require("core.lib")
local setup      = require("program.snabbvmx.lwaftr.setup")

local function show_usage(exit_code)
   print(require("program.snabbvmx.lwaftr.README_inc"))
   if exit_code then main.exit(exit_code) end
end

local function fatal(msg)
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
   local conf_file, sock_path, pci, id1, mac1, id2, mac2, vmxtap
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
       print(string.format("warning: config file %s not found", conf_file))
     end
   end
   function handlers.i(arg)
      id1 = arg
      if not arg then
         fatal("Argument '--id1' was not set")
      end
   end
   function handlers.j(arg)
      id2 = arg
      if not arg then
         fatal("Argument '--id2' was not set")
      end
   end
   function handlers.p(arg)
      pci = arg
      if not arg then
         fatal("Argument '--pci' was not set")
      end
   end
   function handlers.m(arg)
      mac1 = arg
      if not arg then
         fatal("Argument '--mac1' was not set")
      end
   end
   function handlers.n(arg)
      mac2 = arg
      if not arg then
         fatal("Argument '--mac2' was not set")
      end
   end
   function handlers.s(arg)
      sock_path = arg
      if not arg then
         fatal("Argument '--sock' was not set")
      end
   end
   function handlers.t(arg)
      vmxtap = arg
      if not arg then
         fatal("Argument '--tap' was not set")
      end
   end
   function handlers.h() show_usage(0) end
   lib.dogetopt(args, handlers, "c:s:t:i:p:m:j:n:vD:h",
      { ["conf"] = "c", ["sock"] = "s", ["tap"] = "t",
        ["id1"] = "i", ["pci"] = "p", ["mac1"] = "m",
        ["id2"] = "j", ["mac2"] = "n",
        verbose = "v", duration = "D", help = "h" })
   return opts, conf_file, pci, id1, mac1, id2, mac2, sock_path, vmxtap
end

function run(args)
   local opts, conf_file, pci, id1, mac1, id2, mac2, sock_path, vmxtap = parse_args(args)


   local conf = {}
   local lwconf = {}
   local ring_buffer_size = 2048
   local discard_threshold = 100000
   local discard_check_timer = 1
   local discard_wait = 20

   lwconf.ipv6_mtu = 9500
   lwconf.ipv4_mtu = 9500

   if file_exists(conf_file) then
     conf = lib.load_conf(conf_file)
     if not file_exists(conf.lwaftr) then
       fatal(("lwaftr conf file %s not found"):format(conf.lwaftr))
     end
     lwconf = require('apps.lwaftr.conf').load_lwaftr_config(conf.lwaftr)
     lwconf.ipv6_mtu = lwconf.ipv6_mtu or 1500
     lwconf.ipv4_mtu = lwconf.ipv4_mtu or 1460
   else
     ring_buffer_size = 1024
     print(string.format("interface %s set to passhtru mode", id1))
   end

   local c = config.new()

   if conf.settings then
     if conf.settings.ring_buffer_size then
       ring_buffer_size = tonumber(conf.settings.ring_buffer_size)
       if not ring_buffer_size then fatal("bad ring size: " .. conf.settings.ring_buffer_size) end
       if ring_buffer_size > 32*1024 then
         fatal("ring size too large for hardware: " .. ring_buffer_size)
       end
       if math.log(ring_buffer_size)/math.log(2) % 1 ~= 0 then
         fatal("ring size is not a power of two: " .. ring_buffer_size)
       end
     end
   end

   print(string.format("ring_buffer_size set to %d", ring_buffer_size))
   require('apps.intel.intel10g').num_descriptors = ring_buffer_size

   conf.ipv6_interface.pci = pci
   conf.ipv4_interface.pci = pci
   conf.ipv6_interface.mtu = conf.ipv6_interface.mtu or lwconf.ipv6_mtu
   conf.ipv4_interface.mtu = conf.ipv4_interface.mtu or lwconf.ipv4_mtu
   conf.ipv6_interface.mac_address, conf.ipv6_interface.id = mac1, id1
   conf.ipv4_interface.mac_address, conf.ipv4_interface.id = mac2, id2

   if dir_exists(("/sys/devices/virtual/net/%s"):format(id1)) then
     conf.settings.mirror_id = id1
   end

   print (string.format("vmxtap is set to %s", vmxtap))
   setup.lwaftr_app(c, conf, lwconf, sock_path, vmxtap )

   engine.configure(c)

   if opts.verbosity >= 2 then
     local function lnicui_info()
       engine.report_apps()
     end
     local t = timer.new("report", lnicui_info, 1e9, 'repeating')
     timer.activate(t)
   end

   engine.busywait = true
   if opts.duration then
      engine.main({duration=opts.duration, report={showlinks=true}})
   else
      engine.main({report={showlinks=true}})
   end
end
