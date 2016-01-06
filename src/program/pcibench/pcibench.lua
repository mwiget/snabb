module(..., package.seeall)

local app = require("core.app")
local basic_apps = require("apps.basic.basic_apps")
local c_config = require("core.config")
local ipv6 = require("lib.protocol.ipv6")
local ethernet = require("lib.protocol.ethernet")
local lib = require("core.lib")
local pcap = require("apps.pcap.pcap")
local pci = require("lib.hardware.pci")

local long_opts = {
     duration     = "D",
}

function run(args)
  local opt = {}
  local duration
  function opt.D (arg) duration = tonumber(arg)  end
  args = lib.dogetopt(args, opt, "D:", long_opts)
  if not (#args == 4 or #args == 2) then
    print("Usage: pcibench [-D seconds] <pcap1> <pci1> [<pcap2> <pci2>]")
    main.exit(1)
  end

  local pcap1 = table.remove(args, 1)
  local pciaddr1 = table.remove(args, 1)
  local pcap2 = table.remove(args, 1)
  local pciaddr2 = table.remove(args, 1)

  local c = c_config.new()

  local device_info1 = pci.device_info(pciaddr1)
  if not device_info1 then
    print(format("could not find device information for PCI address %s", pciaddr1))
    main.exit(1)
  end

  if pciaddr2 then
    local device_info2 = pci.device_info(pciaddr2)
    if not device_info2 then
      print(format("could not find device information for PCI address %s", pciaddr2))
      main.exit(1)
    end
  end

  config.app(c, "pci1", require(device_info1.driver).driver,
  { pciaddr = pciaddr1, vmdq = false, macaddr = nil, vlan = nil})

  if (pciaddr2) then
    config.app(c, "pci2", require(device_info2.driver).driver,
    { pciaddr = pciaddr2, vmdq = false, macaddr = nil, vlan = nil})
    c_config.app(c, "capture2", pcap.PcapReader, pcap2)
    c_config.app(c, "repeater2", basic_apps.Repeater)
    c_config.app(c, "sink2", basic_apps.Sink)
    c_config.app(c, "pci2_to_pci1", basic_apps.Statistics)
    c_config.app(c, "pci1_to_pci2", basic_apps.Statistics)
  else
    c_config.app(c, "rx", basic_apps.Statistics)
  end

  c_config.app(c, "capture1", pcap.PcapReader, pcap1)
  c_config.app(c, "repeater1", basic_apps.Repeater)
  c_config.app(c, "sink1", basic_apps.Sink)

  c_config.link(c, "capture1.output -> repeater1.input")
  c_config.link(c, "repeater1.output -> pci1.rx")
  if (pciaddr2) then
    c_config.link(c, "pci1.tx -> pci1_to_pci2.input")
    c_config.link(c, "pci1_to_pci2.output -> sink2.input")
    c_config.link(c, "capture2.output -> repeater2.input")
    c_config.link(c, "repeater2.output -> pci2.rx")
    c_config.link(c, "pci2.tx -> pci2_to_pci1.input")
    c_config.link(c, "pci2_to_pci1.output -> sink1.input")
  else
    c_config.link(c, "pci1.tx -> rx.input")
    c_config.link(c, "rx.output -> sink1.input")
  end

  app.configure(c)

  app.main({duration=duration})

end
