module(...,package.seeall)

-- http://tools.ietf.org/html/draft-mkonstan-keyed-ipv6-tunnel-01

local AF_INET6 = 10

local app = require("core.app")
local link = require("core.link")
local packet = require("core.packet")

local lib = require("core.lib")

local bit = require("bit")
local ffi = require("ffi")
local C = ffi.C

local config = require("core.config")
local ethernet = require("lib.protocol.ethernet")
local ipv6 = require("lib.protocol.ipv6")

local receive, transmit = link.receive, link.transmit

local eth_vlan_header_t = ffi.typeof[[
struct {
   // ethernet
   uint8_t  ether_dhost[6];
   uint8_t  ether_shost[6];
   struct {
      uint16_t tpid;
      uint16_t tag;
   } vlan;
   uint16_t ether_type;
} __attribute__((packed))
]]
local eth_vlan_header_ptr_type = ffi.typeof("$*", eth_vlan_header_t)
local eth_vlan_header_size = ffi.sizeof(eth_vlan_header_t)

local ipv6_header_t = ffi.typeof[[
struct {
   // ethernet
   uint8_t  ether_dhost[6];
   uint8_t  ether_shost[6];
   uint16_t ether_type;
   // ipv6
   uint32_t v_tc_fl; // version, tc, flow_label
   uint16_t payload_length;
   uint8_t  next_header;
   uint8_t hop_limit;
   uint8_t src_ip[16];
   uint8_t dst_ip[16];
   // tunnel
   uint32_t session_id;
   uint64_t cookie;
} __attribute__((packed))
]]
local ipv6_header_ptr_type = ffi.typeof("$*", ipv6_header_t)
local ipv6_header_size = ffi.sizeof(ipv6_header_t)

local ipv6_vlan_header_t = ffi.typeof[[
struct {
   // ethernet
   uint8_t  ether_dhost[6];
   uint8_t  ether_shost[6];
   struct {
      uint16_t tpid;
      uint16_t tag;
   } vlan;
   uint16_t ether_type;
   // ipv6
   uint32_t v_tc_fl; // version, tc, flow_label
   uint16_t payload_length;
   uint8_t  next_header;
   uint8_t hop_limit;
   uint8_t src_ip[16];
   uint8_t dst_ip[16];
   // tunnel
   uint32_t session_id;
   uint64_t cookie;
} __attribute__((packed))
]]
local ipv6_vlan_header_ptr_type = ffi.typeof("$*", ipv6_vlan_header_t)
local ipv6_vlan_header_size = ffi.sizeof(ipv6_vlan_header_t)

local o_ethertype_ipv6 = C.htons(0x86DD)
local o_ethertype_8021q = C.htons(0x8100)
local uint16_ptr_t = ffi.typeof('uint16_t*')
local uint32_ptr_t = ffi.typeof('uint32_t*')
local uint64_ptr_t = ffi.typeof('uint64_t*')

local n_cache_src_ipv6 = ipv6:pton("fe80::")
local n_next_hop_mac_empty = ethernet:pton("00:00:00:00:00:00")

local SESSION_COOKIE_SIZE = 12 -- 32 bit session and 64 bit cookie

-- Next Header.
-- Set to 0x73 to indicate that the next header is L2TPv3.
local L2TPV3_NEXT_HEADER = 0x73

local function hex_dump(cdata, len)
  local buf = ffi.string(cdata,len)
  for i=1,math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then io.write(string.format('%08X  ', i-1)) end
    io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
    if i %  8 == 0 then io.write(' ') end
    if i % 16 == 0 then io.write( buf:sub(i-16+1, i):gsub('%c','.'), '\n' ) end
  end
end

function string.tohex(str)
  return (str:gsub('.', function (c)
    return string.format('%02X', string.byte(c))
  end))
end

local function send_ipv6_cache_trigger(link, mac_address, pkt)

   local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data)
   -- In order for loopback selftests to work, use the same source and destination
   -- MAC address in the cache refresh packet. If on return these MAC's are unchanged
   -- then we just learn the same MAC also for the remote tunnel endpoint ;-)
   ffi.copy(ipv6_hdr.ether_dhost, mac_address, 6)
   ffi.copy(ipv6_hdr.src_ip, n_cache_src_ipv6, 16)
   transmit(link, pkt)

end

SimpleKeyedTunnel = {}

local encap_table = {}
local decap_table = {}
local nh_cache_table = {}

local function encap_packet (self, link, pkt)

   local id = self.id
   local mac_address = self.mac_address
   local ipv6_address = self.ipv6_address
   local cache_refresh_interval = self.cache_refresh_interval
   local encap_table = self.encap_table
   local current_time = tonumber(app.now())

   -- tagged traffic from trunk side must be IPv6 encapsulated,
   -- as long as the vlan tag is in the tunnel table
   local ethernet_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data)
   local vlan = bit.band(C.ntohs(ethernet_hdr.vlan.tag), 4095)
   local encap = encap_table[vlan]

   if encap and vlan > 0 then
      local shift_right = ipv6_header_size - 4
      packet.shiftright(pkt, shift_right)
      local orig_eth_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data + shift_right)
      local new_eth_hdr  = ffi.cast(eth_vlan_header_ptr_type, pkt.data + ipv6_header_size)
      ffi.copy(new_eth_hdr.ether_dhost, orig_eth_hdr.ether_dhost, 12)
      local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data)
      ipv6_hdr.ether_type = o_ethertype_ipv6
      ffi.copy(ipv6_hdr.ether_shost, mac_address, 6)
      ipv6_hdr.next_header = L2TPV3_NEXT_HEADER
      ipv6_hdr.src_ip = ipv6_address
      ipv6_hdr.dst_ip = encap.ipv6
      ipv6_hdr.session_id = 0xffffffff
      ipv6_hdr.cookie = encap.lc
      lib.bitfield(32, ipv6_hdr, 'v_tc_fl', 0, 4, 6) -- IPv6 Version
      lib.bitfield(32, ipv6_hdr, 'v_tc_fl', 4, 8, 1) -- Traffic class
      ipv6_hdr.hop_limit = 255
      ipv6_hdr.payload_length = C.htons(pkt.length - ipv6_header_size + 12)
      if current_time > encap.cache_refresh_time + cache_refresh_interval then
         self.cache_refresh_time = current_time
         send_ipv6_cache_trigger(self.output.trunk, mac_address, packet.clone(pkt))
      end
      local ipv6_key = ffi.string(ipv6_hdr.dst_ip, 16)
      local nh_cache =  self.nh_cache_table[ipv6_key] 
      if nh_cache then
         ffi.copy(ipv6_hdr.ether_dhost, nh_cache, 6)
         transmit(link, pkt)
      else
         packet.free(pkt)  -- TODO verify cookies
      end
   else
      print(string.format("%s: vlan id %d NOT found in encap table", id, vlan))
      --      hex_dump(pkt.data, pkt.length)
      transmit(link, packet.clone(pkt))
   end

end

function SimpleKeyedTunnel:new (arg)
   local cfg = arg and config.parse_app_arg(arg) or {}
   local count = 0

  assert( type(cfg.tunnels) == "table", "tunnel config expects an table")

  local ipv6_address = ipv6:pton(cfg.ipv6_address)
  print(string.format("local IPv6 tunnel endpoint: %s", ipv6:ntop(ipv6_address)))

  local single_stick = cfg.single_stick
  if single_stick then
     print("running in single_stick mode")
  end
  local mac_address = n_next_hop_mac_empty
  if cfg.mac_address then
     mac_address = ethernet:pton(cfg.mac_address)
  end

  for _,conf in ipairs(cfg.tunnels) do
  
    count = count + 1

    local ipv6_n = ipv6:pton(conf.ipv6)
    local ipv6_key = ffi.string(ipv6_n, 16)

    local vlan = C.htons(conf.vlan)
    assert (vlan, string.format("vlan id missing for tunnel with IPv6 %s", conf.ipv6))
    local lc = ffi.cast(uint64_ptr_t, lib.hexundump(conf.lc, 8))
    local rc = ffi.cast(uint64_ptr_t, lib.hexundump(conf.rc, 8))
    encap_table[conf.vlan] = { ipv6 = ipv6_n, lc = lc[0], rc = rc[0], 
      cache_refresh_time = 0 }
    decap_table[ipv6_key] = { vlan = vlan, lc = lc[0], rc = rc[0] }

  end

  local o = 
  {
     id = cfg.id,
    mac_address = mac_address,
    ipv6_address = ipv6_address,
    cache_refresh_interval = 1,
    encap_table = encap_table,
    decap_table = decap_table,
    nh_cache_table = nh_cache_table,
    single_stick = single_stick
  }

  print(string.format("%d tunnels parsed", count))
  return setmetatable(o, {__index = SimpleKeyedTunnel})
end

function SimpleKeyedTunnel:push()

   local trunk_in, trunk_out = self.input.trunk, self.output.trunk
   local ipv6_in, ipv6_out = self.input.ipv6, self.output.ipv6

   local id = self.id
   local mac_address = self.mac_address
   local ipv6_address = self.ipv6_address
   local cache_refresh_interval = self.cache_refresh_interval
   local encap_table = self.encap_table
   local decap_table = self.decap_table
   local single_stick = self.single_stick

   -- encapsulation path
   for _=1, link.nreadable(trunk_in) do
      local pkt = receive(trunk_in)
      local ethernet_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data)
      local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data)
      local vlan = bit.band(C.ntohs(ethernet_hdr.vlan.tag), 4095)
      -- print(string.format("%s: rx pkt to encap on vlan %d src=%s dst=%s ether_type=0x%x", id, vlan, ethernet:ntop(ethernet_hdr.ether_shost), ethernet:ntop(ethernet_hdr.ether_dhost), C.ntohs(ipv6_hdr.ether_type)))

      if ethernet_hdr.vlan.tpid == o_ethertype_8021q and vlan > 0 then
         encap_packet(self, ipv6_out, pkt)
      else
         -- untagged traffic must be passed thru, 
         -- but process and drop IPv6 next hop resolve packets for their nh mac 
         -- and IPV6 source address  (TODO)
         local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data)
         if ethernet_hdr.vlan.tpid == o_ethertype_8021q then
            ipv6_hdr = ffi.cast(ipv6_vlan_header_ptr_type, pkt.data)
         end
         if ipv6_hdr.ether_type == o_ethertype_ipv6 and ipv6_hdr.next_header == L2TPV3_NEXT_HEADER then
            local ipv6_key = ffi.string(ipv6_hdr.dst_ip, 16)
            local decap = decap_table[ipv6_key]
            if decap then
               local mac = ethernet:pton("00:00:00:00:00:00")
               ffi.copy(mac, ipv6_hdr.ether_dhost, 6)
               self.nh_cache_table[ipv6_key] = mac
               packet.free(pkt)  -- TODO verify cookies?
            else
               transmit(ipv6_out, pkt)
            end
         else
            transmit(ipv6_out, pkt)
         end

      end
   end

   -- decapsulation path
   for _=1, link.nreadable(ipv6_in) do
      local pkt = receive(ipv6_in)
      local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data)
      if ipv6_hdr.ether_type == o_ethertype_ipv6 then
         if ipv6_hdr.next_header == L2TPV3_NEXT_HEADER then
            local ipv6_key = ffi.string(ipv6_hdr.src_ip, 16)
            local decap = decap_table[ipv6_key]
            if decap then
               if ipv6_hdr.cookie == decap.rc then
                  local payload_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data + ipv6_header_size)
                  -- copy ethernet header and ether type to the front of the decapped packet
                  -- yes, this overwrites the IPv6 header we no longer need
                  local eth_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data)
                  ffi.copy(eth_hdr.ether_dhost, payload_hdr.ether_dhost, 12)
                  eth_hdr.vlan.tpid = o_ethertype_8021q
                  eth_hdr.vlan.tag = decap.vlan
                  ffi.copy(pkt.data + eth_vlan_header_size - 2, pkt.data + ipv6_header_size + 12, 
                     pkt.length - ipv6_header_size)
                  pkt.length = pkt.length - ipv6_header_size + eth_vlan_header_size
                  if single_stick then
                     transmit(ipv6_out, pkt)
                  else
                     transmit(trunk_out, pkt)
                  end
               else
                  print("cookie doesn't match")
                  packet.free(pkt)  -- TODO verify cookies
               end
                   
            else
               print(string.format("no match for IPv6 source %s found in decap table", ipv6:ntop(ipv6_hdr.src_ip)))
               packet.free(pkt)  -- TODO
            end
         else
            transmit(trunk_out, pkt)
         end
      else
         if single_stick then
            encap_packet(self, ipv6_out, pkt)
         end
      end
   end

end


function selftest ()
   print("Keyed IPv6 tunnel selftest")
   local ok = true
local pcap = require("apps.pcap.pcap")
local basic_apps = require("apps.basic.basic_apps")

   local input_file = "apps/keyed_ipv6_tunnel/selftest.cap.input"
   local output_file = "apps/keyed_ipv6_tunnel/selftest.cap.output"
   local tunnel_config = {
      local_address = "00::2:1",
      remote_address = "00::2:1",
      local_cookie = "12345678",
      remote_cookie = "12345678",
      default_gateway_MAC = "a1:b2:c3:d4:e5:f6"
   } -- should be symmetric for local "loop-back" test

   local c = config.new()
   config.app(c, "source", pcap.PcapReader, input_file)
   config.app(c, "tunnel", SimpleKeyedTunnel, tunnel_config)
   config.app(c, "sink", pcap.PcapWriter, output_file)
   config.link(c, "source.output -> tunnel.trunk")
   config.link(c, "tunnel.ipv6 -> tunnel.ipv6")
   config.link(c, "tunnel.trunk -> sink.input")
   app.configure(c)

   app.main({duration = 0.25}) -- should be long enough...
   -- Check results
   if io.open(input_file):read('*a') ~=
      io.open(output_file):read('*a')
   then
      ok = false
   end

   local c = config.new()
   config.app(c, "source", basic_apps.Source)
   config.app(c, "tunnel", SimpleKeyedTunnel, tunnel_config)
   config.app(c, "sink", basic_apps.Sink)
   config.link(c, "source.output -> tunnel.decapsulated")
   config.link(c, "tunnel.ipv6 -> tunnel.ipv6")
   config.link(c, "tunnel.decapsulated -> sink.input")
   app.configure(c)

   print("run simple one second benchmark ...")
   app.main({duration = 1})

   if not ok then
      print("selftest failed")
      os.exit(1)
   end
   print("selftest passed")

end
