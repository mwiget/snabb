module(..., package.seeall)

local config     = require("core.config")
local Intel82599 = require("apps.intel.intel_app").Intel82599
local PcapFilter = require("apps.packet_filter.pcap_filter").PcapFilter
local VirtioNet  = require("apps.virtio_net.virtio_net").VirtioNet
local lwaftr     = require("apps.lwaftr.lwaftr")
local basic_apps = require("apps.basic.basic_apps")
local pcap       = require("apps.pcap.pcap")
local bt         = require("apps.lwaftr.binding_table")
local ipv4_apps  = require("apps.lwaftr.ipv4_apps")
local ipv6_apps  = require("apps.lwaftr.ipv6_apps")
local vlan       = require("apps.vlan.vlan")
local ethernet   = require("lib.protocol.ethernet")

function lwaftr_app(c, conf)
   assert(type(conf) == 'table')
   conf.preloaded_binding_table = bt.load(conf.binding_table)
   local function append(t, elem) table.insert(t, elem) end
   local function prepend(t, elem) table.insert(t, 1, elem) end

   config.app(c, "reassemblerv4", ipv4_apps.Reassembler, {})
   config.app(c, "reassemblerv6", ipv6_apps.Reassembler, {})
   config.app(c, "icmpechov4", ipv4_apps.ICMPEcho, { address = conf.aftr_ipv4_ip })
   config.app(c, 'lwaftr', lwaftr.LwAftr, conf)
   config.app(c, "icmpechov6", ipv6_apps.ICMPEcho, { address = conf.aftr_ipv6_ip })
   config.app(c, "fragmenterv4", ipv4_apps.Fragmenter,
              { mtu=conf.ipv4_mtu })
   config.app(c, "fragmenterv6", ipv6_apps.Fragmenter,
              { mtu=conf.ipv6_mtu })
   config.app(c, "ndp", ipv6_apps.NDP,
              { src_ipv6 = conf.aftr_ipv6_ip, src_eth = conf.aftr_mac_b4_side,
                dst_eth = conf.next_hop6_mac, dst_ipv6 = conf.next_hop_ipv6_addr,
                all_ipv6_addrs = conf.preloaded_binding_table:get_br_addresses() })

   local preprocessing_apps_v4  = { "reassemblerv4" }
   local preprocessing_apps_v6  = { "reassemblerv6" }
   local postprocessing_apps_v4  = { "fragmenterv4" }
   local postprocessing_apps_v6  = { "fragmenterv6" }

   if conf.ipv4_ingress_filter then
      config.app(c, "ingress_filterv4", PcapFilter, { filter = conf.ipv4_ingress_filter })
      append(preprocessing_apps_v4, "ingress_filterv4")
   end
   if conf.ipv6_ingress_filter then
      config.app(c, "ingress_filterv6", PcapFilter, { filter = conf.ipv6_ingress_filter })
      append(preprocessing_apps_v6, "ingress_filterv6")
   end
   if conf.ipv4_egress_filter then
      config.app(c, "egress_filterv4", PcapFilter, { filter = conf.ipv4_egress_filter })
      prepend(postprocessing_apps_v4, "egress_filterv4")
   end
   if conf.ipv6_egress_filter then
      config.app(c, "egress_filterv6", PcapFilter, { filter = conf.ipv6_egress_filter })
      prepend(postprocessing_apps_v6, "egress_filterv6")
   end

   append(preprocessing_apps_v4,   { name = "icmpechov4", input = "south", output = "north" })
   prepend(postprocessing_apps_v4, { name = "icmpechov4", input = "north", output = "south" })

   append(preprocessing_apps_v6,   { name = "ndp",        input = "south", output = "north" })
   append(preprocessing_apps_v6,   { name = "icmpechov6", input = "south", output = "north" })
   prepend(postprocessing_apps_v6, { name = "icmpechov6", input = "north", output = "south" })
   prepend(postprocessing_apps_v6, { name = "ndp",        input = "north", output = "south" })

   set_preprocessors(c, preprocessing_apps_v4, "lwaftr.v4")
   set_preprocessors(c, preprocessing_apps_v6, "lwaftr.v6")
   set_postprocessors(c, "lwaftr.v6", postprocessing_apps_v6)
   set_postprocessors(c, "lwaftr.v4", postprocessing_apps_v4)
end

local function link_apps(c, apps)
   for i=1, #apps - 1 do
      local output, input = "output", "input"
      local src, dst = apps[i], apps[i+1]
      if type(src) == "table" then
         src, output = src["name"], src["output"]
      end
      if type(dst) == "table" then
         dst, input = dst["name"], dst["input"]
      end
      config.link(c, ("%s.%s -> %s.%s"):format(src, output, dst, input))
   end
end

function set_preprocessors(c, apps, dst)
   assert(type(apps) == "table")
   link_apps(c, apps)
   local last_app, output = apps[#apps], "output"
   if type(last_app) == "table" then
      last_app, output = last_app.name, last_app.output
   end
   config.link(c, ("%s.%s -> %s"):format(last_app, output, dst))
end

function set_postprocessors(c, src, apps)
   assert(type(apps) == "table")
   local first_app, input = apps[1], "input"
   if type(first_app) == "table" then
      first_app, input = first_app.name, first_app.input
   end
   config.link(c, ("%s -> %s.%s"):format(src, first_app, input))
   link_apps(c, apps)
end

function link_source(c, v4_in, v6_in)
   config.link(c, v4_in..' -> reassemblerv4.input')
   config.link(c, v6_in..' -> reassemblerv6.input')
end

function link_sink(c, v4_out, v6_out)
   config.link(c, 'fragmenterv4.output -> '..v4_out)
   config.link(c, 'fragmenterv6.output -> '..v6_out)
end

function load_phy(c, conf, v4_nic_name, v4_nic_pci, v6_nic_name, v6_nic_pci)
   lwaftr_app(c, conf)

   config.app(c, v4_nic_name, Intel82599, {
      pciaddr=v4_nic_pci,
      vmdq=conf.vlan_tagging,
      vlan=conf.vlan_tagging and conf.v4_vlan_tag,
      rxcounter=1,
      macaddr=ethernet:ntop(conf.aftr_mac_inet_side)})
   config.app(c, v6_nic_name, Intel82599, {
      pciaddr=v6_nic_pci,
      vmdq=conf.vlan_tagging,
      vlan=conf.vlan_tagging and conf.v6_vlan_tag,
      rxcounter=1,
      macaddr = ethernet:ntop(conf.aftr_mac_b4_side)})

   link_source(c, v4_nic_name..'.tx', v6_nic_name..'.tx')
   link_sink(c, v4_nic_name..'.rx', v6_nic_name..'.rx')
end

function load_virt(c, conf, v4_nic_name, v4_nic_pci, v6_nic_name, v6_nic_pci)
   lwaftr_app(c, conf)

   config.app(c, v4_nic_name, VirtioNet, {
      pciaddr=v4_nic_pci,
      vlan=conf.vlan_tagging and conf.v4_vlan_tag,
      macaddr=ethernet:ntop(conf.aftr_mac_inet_side)})
   config.app(c, v6_nic_name, VirtioNet, {
      pciaddr=v6_nic_pci,
      vlan=conf.vlan_tagging and conf.v6_vlan_tag,
      macaddr = ethernet:ntop(conf.aftr_mac_b4_side)})

   link_source(c, v4_nic_name..'.tx', v6_nic_name..'.tx')
   link_sink(c, v4_nic_name..'.rx', v6_nic_name..'.rx')
end

function load_bench(c, conf, v4_pcap, v6_pcap, v4_sink, v6_sink)
   lwaftr_app(c, conf)

   config.app(c, "capturev4", pcap.PcapReader, v4_pcap)
   config.app(c, "capturev6", pcap.PcapReader, v6_pcap)
   config.app(c, "repeaterv4", basic_apps.Repeater)
   config.app(c, "repeaterv6", basic_apps.Repeater)
   if conf.vlan_tagging then
      config.app(c, "untagv4", vlan.Untagger, { tag=conf.v4_vlan_tag })
      config.app(c, "untagv6", vlan.Untagger, { tag=conf.v6_vlan_tag })
   end
   config.app(c, v4_sink, basic_apps.Sink)
   config.app(c, v6_sink, basic_apps.Sink)

   config.link(c, "capturev4.output -> repeaterv4.input")
   config.link(c, "capturev6.output -> repeaterv6.input")

   if conf.vlan_tagging then
      config.link(c, "repeaterv4.output -> untagv4.input")
      config.link(c, "repeaterv6.output -> untagv6.input")
      link_source(c, 'untagv4.output', 'untagv6.output')
   else
      link_source(c, 'repeaterv4.output', 'repeaterv6.output')
   end
   link_sink(c, v4_sink..'.input', v6_sink..'.input')
end

function load_check(c, conf, inv4_pcap, inv6_pcap, outv4_pcap, outv6_pcap)
   lwaftr_app(c, conf)

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

   if conf.vlan_tagging then
      config.link(c, "capturev4.output -> untagv4.input")
      config.link(c, "capturev6.output -> untagv6.input")
      link_source(c, 'untagv4.output', 'untagv6.output')

      link_sink(c, 'tagv4.input', 'tagv6.input')
      config.link(c, "tagv4.output -> output_filev4.input")
      config.link(c, "tagv6.output -> output_filev6.input")
   else
      link_source(c, 'capturev4.output', 'capturev6.output')
      link_sink(c, 'output_filev4.input', 'output_filev6.input')
   end
end
