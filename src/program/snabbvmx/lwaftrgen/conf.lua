module(..., package.seeall)

local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local Parser = require("apps.lwaftr.conf_parser").Parser

policies = {
   DROP = 1,
   ALLOW = 2
}

local function required(key)
   return function(config)
      error('missing required configuration key "'..key..'"')
   end
end

local function required_if(key, otherkey)
   return function(config)
      if config[otherkey] then
         error('missing required configuration key "'..key..'"')
      end
   end
end

local function required_at_least_one_of(key, otherkey)
   return function(config)
      if config[otherkey] == nil then
         error(string.format("At least one of '%s' and '%s' must be specified", key, otherkey))
      end
   end
end

local function default(val)
   return function(config) return val end
end

local lwaftrgen_conf_spec = {
   parse={
      vlan_tagging=Parser.parse_boolean,
      dst_mac=Parser.parse_mac,
      count=Parser.parse_non_negative_number,
      rate=Parser.parse_non_negative_number,
      aftr_ipv6=Parser.parse_ipv6,
      b4_ipv6=Parser.parse_ipv6,
      public_ipv4=Parser.parse_ipv4,
      b4_ipv4=Parser.parse_ipv4,
      b4_port=Parser.parse_non_negative_number,
      sizes=Parser.parse_string_or_file,
   },
   defaults={
      vlan_tagging=default(false),
      dst_mac=required('dst_mac'),
      count=default(1),
      aftr_ipv6=required('aftr_ipv6'),
      b4_ipv4=default('8.8.8.8'),
      public_ipv4=required('aftr_ipv6'),
      b4_port=default(1024),
      v4_vlan_tag=required_if('v4_vlan_tag', 'vlan_tagging'),
      v6_vlan_tag=required_if('v6_vlan_tag', 'vlan_tagging'),
      sizes=default('64,64,64,64,64,64,64,594,594,594,1500'),
   },
   validate=function(parser, config) end
}

function load_lwaftrgen_config(stream)
   return Parser.new(stream):parse_property_list(lwaftrgen_conf_spec)
end

function selftest()
   print('selftest: conf')
   local lib = require('core.lib')
   local function string_file(str)
      local pos = 1
      return {
         read = function(self, n)
            assert(n==1)
            local ret
            if pos <= #str then
               ret = str:sub(pos,pos)
               pos = pos + 1
            end
            return ret
         end,
         close = function(self) str = nil end
      }
   end
   local function test(str, expected)
      if not lib.equal(expected, load_lwaftr_config(string_file(str))) then
         error('lwaftrgen conf parse produced unexpected result; string:\n'..str)
      end
   end
   test([[
            aftr_ipv4_ip = 1.2.3.4
            aftr_ipv6_ip = 8:9:a:b:c:d:e:f
            aftr_mac_b4_side = 22:22:22:22:22:22
            aftr_mac_inet_side = 12:12:12:12:12:12
            next_hop6_mac = 44:44:44:44:44:44
            binding_table = "foo-table.txt"
            hairpinning = false
            icmpv4_rate_limiter_n_packets=6e3
            icmpv4_rate_limiter_n_seconds=2
            icmpv6_rate_limiter_n_packets=6e3
            icmpv6_rate_limiter_n_seconds=2
            inet_mac = 68:68:68:68:68:68
            ipv4_mtu = 1460
            ipv6_mtu = 1500
            max_fragments_per_reassembly_packet = 20
            max_ipv4_reassembly_packets = 100
            max_ipv6_reassembly_packets = 50
            policy_icmpv4_incoming = ALLOW
            policy_icmpv6_incoming = ALLOW
            policy_icmpv4_outgoing = ALLOW
            policy_icmpv6_outgoing = ALLOW
            v4_vlan_tag = 1092 # 0x444
            v6_vlan_tag = 1638 # 0x666
            vlan_tagging = true
        ]],
      {
         aftr_ipv4_ip = ipv4:pton('1.2.3.4'),
         aftr_ipv6_ip = ipv6:pton('8:9:a:b:c:d:e:f'),
         aftr_mac_b4_side = ethernet:pton("22:22:22:22:22:22"),
         aftr_mac_inet_side = ethernet:pton("12:12:12:12:12:12"),
         next_hop6_mac = ethernet:pton("44:44:44:44:44:44"),
         binding_table = "foo-table.txt",
         hairpinning = false,
         icmpv4_rate_limiter_n_packets=6e3,
         icmpv4_rate_limiter_n_seconds=2,
         icmpv6_rate_limiter_n_packets=6e3,
         icmpv6_rate_limiter_n_seconds=2,
         inet_mac = ethernet:pton("68:68:68:68:68:68"),
         ipv4_mtu = 1460,
         ipv6_mtu = 1500,
         max_fragments_per_reassembly_packet = 20,
         max_ipv4_reassembly_packets = 100,
         max_ipv6_reassembly_packets = 50,
         policy_icmpv4_incoming = policies['ALLOW'],
         policy_icmpv6_incoming = policies['ALLOW'],
         policy_icmpv4_outgoing = policies['ALLOW'],
         policy_icmpv6_outgoing = policies['ALLOW'],
         v4_vlan_tag = 0x444,
         v6_vlan_tag = 0x666,
         vlan_tagging = true
      }
   )
   local function test_loading_filter_conf_from_file()
      -- Setup the filter conf file.
      local filter_path = os.tmpname()
      local filter_text = 'some pflang filter string'
      assert(lib.writefile(filter_path, filter_text))
      -- Setup the main config file.
      local conf_text = [[
         aftr_ipv4_ip = 1.2.3.4
         aftr_ipv6_ip = 8:9:a:b:c:d:e:f
         aftr_mac_b4_side = 22:22:22:22:22:22
         aftr_mac_inet_side = 12:12:12:12:12:12
         next_hop6_mac = 44:44:44:44:44:44
         binding_table = "foo-table.txt"
         inet_mac = 68:68:68:68:68:68
         ipv4_ingress_filter = <%s
      ]]
      conf_text = conf_text:format(filter_path)
      local conf_table = load_lwaftr_config(string_file(conf_text))
      assert(os.remove(filter_path))
      if conf_table['ipv4_ingress_filter'] ~= filter_text then
         error('lwaftr: filter conf contents do not match; pathname:\n'..filter_path)
      end
   end
   test_loading_filter_conf_from_file()
   print('ok')
end
