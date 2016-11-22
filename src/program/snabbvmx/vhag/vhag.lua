module(..., package.seeall)

local config = require("core.config")
local constants = require("apps.lwaftr.constants")
local ingress_drop_monitor = require("lib.timers.ingress_drop_monitor")
local intel10g = require("apps.intel.intel10g")
local lib = require("core.lib")
-- local lwcounter = require("apps.lwaftr.lwcounter")
local lwtypes = require("apps.lwaftr.lwtypes")
local lwutil = require("apps.lwaftr.lwutil")
local setup = require("program.snabbvmx.vhag.setup")
local shm = require("core.shm")

local fatal, file_exists = lwutil.fatal, lwutil.file_exists

local DEFAULT_MTU = 9500

local function show_usage (exit_code)
  print(require("program.snabbvmx.vhag.README_inc"))
  main.exit(exit_code)
end

function parse_args (args)
  if #args == 0 then show_usage(1) end
  local conf_file, id, access, trunk, mac_address
  local opts = { verbosity = 0 }
  local handlers = {}
  function handlers.v () opts.verbosity = opts.verbosity + 1 end
  function handlers.D (arg)
    opts.duration = assert(tonumber(arg), "Duration must be a number")
  end
  function handlers.c(arg)
    conf_file = arg
    if not arg then
      fatal("Argument '--conf' was not set")
    end
    if not file_exists(conf_file) then
      print(("Warning: config file %s not found"):format(conf_file))
    end
  end
  function handlers.i(arg)
    id = arg
    if not arg then
      fatal("Argument '--id' was not set")
    end
  end
  function handlers.a(arg)
    access = arg
    if not arg then
      fatal("Argument '--access' was not set")
    end
  end
  function handlers.t(arg)
    trunk = arg
    if not arg then
      fatal("Argument '--trunk' was not set")
    end
  end
  function handlers.m(arg)
    mac_address = arg
    if not arg then
      fatal("Argument '--mac_address' was not set")
    end
  end
  function handlers.h() show_usage(0) end
  lib.dogetopt(args, handlers, "c:t:i:a:m:vD:h", {
    ["conf"] = "c", ["trunk"] = "t", ["id"] = "i", ["access"] = "a", ["mac_address"] = "m",
    verbose = "v", duration = "D", help = "h" 
  })
--  print(("mac_address=%s"):format(mac_address))
  return opts, conf_file, id, trunk, access, mac_address

end

local function effective_vlan (conf, vhag)
  if vhag.vlan_tag then
    return lwconf.v4_vlan_tag
  end
  return false
end

function run(args)
  local opts, conf_file, id, trunk, access, mac_address = parse_args(args)

  print(("mac_address=%s"):format(mac_address))

  local conf = {}
  local ring_buffer_size = 2048

  local ingress_drop_action = "flush"
  local ingress_drop_threshold = 100000
  local ingress_drop_interval = 1e6
  local ingress_drop_wait = 20

  if file_exists(conf_file) then
    conf = lib.load_conf(conf_file)
    conf.mtu = conf.mtu or DEFAULT_MTU
  else
    print(("Interface '%s' set to passthru mode"):format(id))
    ring_buffer_size = 1024
    conf.settings = {}
  end

  if conf.settings then
    if conf.settings.ingress_drop_monitor then
      ingress_drop_action = conf.settings.ingress_drop_monitor
    end
    if conf.settings.ingress_drop_threshold then
      ingress_drop_threshold = conf.settings.ingress_drop_threshold
    end
    if conf.settings.ingress_drop_interval then
      ingress_drop_interval = conf.settings.ingress_drop_interval
    end
    if conf.settings.ingress_drop_wait then
      ingress_drop_wait = conf.settings.ingress_drop_wait
    end
  end

  intel10g.ring_buffer_size(ring_buffer_size)

  if id then
    local vhag_id = shm.create("nic/id", lwtypes.lwaftr_id_type)
    vhag_id.value = id
  end

  local mtu = DEFAULT_MTU
  if conf.mtu then
    mtu = conf.mtu
  end
  local vlan
  if conf.vlan then
    vlan = conf.vlan
    mtu = mtu + 4
  end
  conf.id = id
  print(("access=%s"):format(access))
  conf.access = {
    mac_address = mac_address,
    interface = access,
    mtu = mtu,
    vlan = vlan,
  }
  if trunk then
    print(("trunk=%s"):format(trunk))
    conf.trunk = {
      mac_address = mac_address,
      interface = trunk,
      mtu = mtu,
      vlan = vlan,
    }
  end

  local c = config.new()
  setup.vhag_app(c, conf)
  engine.configure(c)

  if opts.verbosity >= 2 then
    local function lnicui_info()
      engine.report_apps()
    end
    local t = timer.new("report", lnicui_info, 1e9, 'repeating')
    timer.activate(t)
  end

  if ingress_drop_action then
    assert(ingress_drop_action == "flush" or ingress_drop_action == "warn",
    "Not valid ingress-drop-monitor action")
    print(("Ingress drop monitor: %s (threshold: %d packets; wait: %d seconds; interval: %.2f seconds)"):format(
    ingress_drop_action, ingress_drop_threshold, ingress_drop_wait, 1e6/ingress_drop_interval))
--    local counter_path = lwcounter.counters_dir.."/ingress-packet-drops"
    local mon = ingress_drop_monitor.new({
      action = ingress_drop_action,
      threshold = ingress_drop_threshold,
      wait = ingress_drop_wait,
--      counter = counter_path,
    })
    timer.activate(mon:timer(ingress_drop_interval))
  end

  engine.busywait = true
  if opts.duration then
    engine.main({duration=opts.duration, report={showlinks=true}})
  else
    engine.main({report={showlinks=true}})
  end
end
