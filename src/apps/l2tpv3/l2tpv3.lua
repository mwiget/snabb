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

local counter = require("core.counter")

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

   local ipv6_vlan_hdr = ffi.cast(ipv6_vlan_header_ptr_type, pkt.data)
   -- In order for loopback selftests to work, use the same source and destination
   -- MAC address in the cache refresh packet. If on return these MAC's are unchanged
   -- then we just learn the same MAC also for the remote tunnel endpoint ;-)
   ffi.copy(ipv6_vlan_hdr.ether_dhost, mac_address, 6)
   ffi.copy(ipv6_vlan_hdr.src_ip, n_cache_src_ipv6, 16)
   counter.add(NhsentPacket)
   counter.add(NhsentByte, pkt.length)
--   hex_dump(pkt.data, pkt.length)

   transmit(link, pkt)

end

SimpleKeyedTunnel = {}

local encap_table = {}
local decap_table = {}
local nh_cache_table = {}

-- Counters for statistics.
v6sentPacket     = counter.open("l2tpv3_v6/sentPacket")
v6sentByte       = counter.open("l2tpv3_v6/sentByte")
v6rcvdPacket     = counter.open("l2tpv3_v6/rcvdPacket")
v6rcvdByte       = counter.open("l2tpv3_v6/rcvdByte")
v6droppedPacket  = counter.open("l2tpv3_v6/droppedPacket")
v6droppedByte    = counter.open("l2tpv3_v6/droppedByte")
v6bridgedPacket  = counter.open("l2tpv3_v6/bridgedPacket")
v6bridgedByte    = counter.open("l2tpv3_v6/bridgedByte")
v6invalidCookie  = counter.open("l2tpv3_v6/invalidCookie")

NhsentPacket    = counter.open("l2tpv3_nh/sentPacket")
NhsentByte      = counter.open("l2tpv3_nh/sentByte")
NhrcvdPacket    = counter.open("l2tpv3_nh/rcvdPacket")
NhrcvdByte      = counter.open("l2tpv3_nh/rcvdByte")

trsentPacket     = counter.open("l2tpv3_trunk/sentPacket")
trsentByte       = counter.open("l2tpv3_trunk/sentByte")
trrcvdPacket     = counter.open("l2tpv3_trunk/rcvdPacket")
trrcvdByte       = counter.open("l2tpv3_trunk/rcvdByte")
trdroppedPacket  = counter.open("l2tpv3_trunk/droppedPacket")
trdroppedByte    = counter.open("l2tpv3_trunk/droppedByte")
trbridgedPacket  = counter.open("l2tpv3_trunk/bridgedPacket")
trbridgedByte    = counter.open("l2tpv3_trunk/bridgedByte")
trinvalidCookie  = counter.open("l2tpv3_trunk/invalidCookie")

local function encap_packet (self, link, pkt)

   local id = self.id
   local mac_address = self.mac_address
   local ipv6_address = self.ipv6_address
   local l2tpv3_vlan = C.htons(self.l2tpv3_vlan)
   local cache_refresh_interval = self.cache_refresh_interval
   local encap_table = self.encap_table
   local current_time = tonumber(app.now())

   -- tagged traffic from trunk side must be IPv6 encapsulated,
   -- as long as the vlan tag is in the tunnel table
   local ethernet_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data)

   local vlan = bit.band(C.ntohs(ethernet_hdr.vlan.tag), 4095)
   local encap = encap_table[vlan]

   counter.add(trrcvdPacket)
   counter.add(trrcvdByte, pkt.length)

   if encap then
--      local shift_right = ipv6_header_size - 4
      local shift_right = ipv6_header_size
      packet.shiftright(pkt, shift_right)
      local orig_eth_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data + shift_right)
      local new_eth_hdr  = ffi.cast(eth_vlan_header_ptr_type, pkt.data + ipv6_vlan_header_size)
      ffi.copy(new_eth_hdr.ether_dhost, orig_eth_hdr.ether_dhost, 12)
      local ipv6_vlan_hdr = ffi.cast(ipv6_vlan_header_ptr_type, pkt.data)
      ipv6_vlan_hdr.vlan.tag = l2tpv3_vlan
      ipv6_vlan_hdr.ether_type = o_ethertype_ipv6
      ffi.copy(ipv6_vlan_hdr.ether_shost, mac_address, 6)
      ipv6_vlan_hdr.next_header = L2TPV3_NEXT_HEADER
      ipv6_vlan_hdr.src_ip = ipv6_address
      ipv6_vlan_hdr.dst_ip = encap.ipv6
      ipv6_vlan_hdr.session_id = 0xffffffff
      ipv6_vlan_hdr.cookie = encap.lc
      lib.bitfield(32, ipv6_vlan_hdr, 'v_tc_fl', 0, 4, 6) -- IPv6 Version
      lib.bitfield(32, ipv6_vlan_hdr, 'v_tc_fl', 4, 8, 1) -- Traffic class
      ipv6_vlan_hdr.hop_limit = 255
      ipv6_vlan_hdr.payload_length = C.htons(pkt.length - ipv6_vlan_header_size + 12)
      
--      print("sending clone to ipv6")
--      transmit(link, packet.clone(pkt))

      if current_time > encap.cache_refresh_time + cache_refresh_interval then
         self.encap_table[vlan].cache_refresh_time = current_time
         -- print(string.format("nh refresh trigger for vlan %d", vlan))
         send_ipv6_cache_trigger(self.output.trunk, mac_address, packet.clone(pkt))
      end
      local ipv6_key = ffi.string(ipv6_vlan_hdr.dst_ip, 16)
      local nh_cache =  self.nh_cache_table[ipv6_key] 
      if nh_cache then

         ffi.copy(ipv6_vlan_hdr.ether_dhost, nh_cache, 6)
         counter.add(v6sentPacket)
         counter.add(v6sentByte, pkt.length)
         transmit(link, pkt)
      else
         -- print(string.format("%s: no nh for ipv6 %s",id , ipv6:ntop(ipv6_vlan_hdr.dst_ip)))
         counter.add(v6droppedPacket)
         counter.add(v6droppedByte, pkt.length)
         packet.free(pkt)  -- TODO verify cookies
      end
   else
      -- print(string.format("%s: vlan id %d NOT found in encap table", id, vlan))
      --      hex_dump(pkt.data, pkt.length)
      counter.add(v6bridgedPacket)
      counter.add(v6bridgedByte, pkt.length)
      transmit(link, pkt)
   end

end

function SimpleKeyedTunnel:new (arg)
   local cfg = arg and config.parse_app_arg(arg) or {}
   local count = 0

  assert( type(cfg.tunnels) == "table", "tunnel config expects an table")

  local ipv6_address = ipv6:pton(cfg.ipv6_address)
  print(string.format("local IPv6 tunnel endpoint: %s", ipv6:ntop(ipv6_address)))

  local l2tpv3_vlan = cfg.vlan
  if l2tpv3_vlan then
     print(string.format("L2TPv3 traffic tagged with vlan %d", l2tpv3_vlan))
  else
     l2tpv3_vlan = 0
  end
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
    assert (string.len(conf.lc) == 8, string.format("Local cookie must be 8 bytes: '%s'", conf.lc))
    local lc = ffi.cast(uint64_ptr_t, lib.hexundump(conf.lc, 8))
    assert (string.len(conf.rc) == 8, string.format("Remote cookie must be 8 bytes: '%s'", conf.rc))
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
    l2tpv3_vlan = l2tpv3_vlan,
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
   local l2tpv3_vlan = self.l2tpv3_vlan
   local cache_refresh_interval = self.cache_refresh_interval
   local encap_table = self.encap_table
   local decap_table = self.decap_table
   local single_stick = self.single_stick

   -- encapsulation path with tagged ethernet packets from virtio 
   -- packets with vlan matching the vlan used to transport L2TPv3 packets
   -- are bridged thru (so ICMP, NDP etc work). 
   -- Same for vlans not found in the tunnel table (done in encap_packet())

   for _=1, link.nreadable(trunk_in) do
      local pkt = receive(trunk_in)
      local ethernet_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data)
      local vlan = bit.band(C.ntohs(ethernet_hdr.vlan.tag), 4095)

      if ethernet_hdr.vlan.tpid == o_ethertype_8021q and vlan ~= l2tpv3_vlan then
         encap_packet(self, ipv6_out, pkt)
      else
         -- L2TPv3 packets (untagged or with vlan matching l2tpv3_vlan) have been 
         -- sent by this app to the virtio interface for next hop resolution.
         -- Learn and drop.
         local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data)
         if ethernet_hdr.vlan.tpid == o_ethertype_8021q then
            ipv6_hdr = ffi.cast(ipv6_vlan_header_ptr_type, pkt.data)
         end
         if ipv6_hdr.ether_type == o_ethertype_ipv6 
            and ipv6_hdr.next_header == L2TPV3_NEXT_HEADER then
            local ipv6_key = ffi.string(ipv6_hdr.dst_ip, 16)
            local decap = decap_table[ipv6_key]
            if decap then
               local mac = ethernet:pton("00:00:00:00:00:00")
               ffi.copy(mac, ipv6_hdr.ether_dhost, 6)
               self.nh_cache_table[ipv6_key] = mac

               -- print(string.format("%s:nh cache for %s at %s", id, ipv6:ntop(ipv6_hdr.dst_ip), ethernet:ntop(mac)))
               counter.add(NhrcvdPacket)
               counter.add(NhrcvdByte, pkt.length)
               packet.free(pkt)
            else
               -- print(string.format("%s cache miss for %s", id, ipv6:ntop(ipv6_hdr.dst_ip)))
               counter.add(v6bridgedPacket)
               counter.add(v6bridgedByte, pkt.length)
               transmit(ipv6_out, pkt)
            end
         else
            counter.add(v6bridgedPacket)
            counter.add(v6bridgedByte, pkt.length)
            transmit(ipv6_out, pkt)
         end
      end
   end

   -- decapsulation path
   for _=1, link.nreadable(ipv6_in) do
      local pkt = receive(ipv6_in)

      local ipv6_vlan_hdr = ffi.cast(ipv6_vlan_header_ptr_type, pkt.data)
      --print(string.format("%s decap pkt received. ether_type=%x", id, C.ntohs(ipv6_vlan_hdr.ether_type)))

      if ipv6_vlan_hdr.ether_type == o_ethertype_ipv6 
         and ipv6_vlan_hdr.next_header == L2TPV3_NEXT_HEADER then
         counter.add(v6rcvdPacket)
         counter.add(v6rcvdByte, pkt.length)
         local ipv6_key = ffi.string(ipv6_vlan_hdr.src_ip, 16)
         local decap = decap_table[ipv6_key]
         -- if no match found, the packet will be bridged
         if decap then
            if ipv6_vlan_hdr.cookie == decap.rc then
               local payload_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data + ipv6_vlan_header_size)
               -- copy ethernet header and ether type to the front of the decapped packet
               -- yes, this overwrites the IPv6 header we no longer need
               local eth_hdr = ffi.cast(eth_vlan_header_ptr_type, pkt.data)
               ffi.copy(eth_hdr.ether_dhost, payload_hdr.ether_dhost, 12)
               eth_hdr.vlan.tpid = o_ethertype_8021q
               eth_hdr.vlan.tag = decap.vlan
--               print(string.format("%s: offset=%d", id, ))
               ffi.copy(pkt.data + eth_vlan_header_size - 2, pkt.data + ipv6_vlan_header_size + 12, 
               pkt.length - ipv6_vlan_header_size)
               pkt.length = pkt.length - ipv6_vlan_header_size + eth_vlan_header_size
               counter.add(trsentPacket)
               counter.add(trsentByte, pkt.length)
               if single_stick then
                  transmit(ipv6_out, pkt)
               else
                  transmit(trunk_out, pkt)
               end
               pkt = nil
            else
               -- print("cookie doesn't match")
               counter.add(v6invalidCookie)
               counter.add(v6droppedPacket)
               counter.add(v6droppedByte, pkt.length)
               packet.free(pkt)
               pkt = nil
            end
         end
      else
      end

      if pkt then
         local vlan = bit.band(C.ntohs(ipv6_vlan_hdr.vlan.tag), 4095)
         if single_stick and vlan ~= l2tpv3_vlan then
            encap_packet(self, ipv6_out, pkt)
         else
            counter.add(trbridgedPacket)
            counter.add(trbridgedByte, pkt.length)
            transmit(trunk_out, pkt)
         end
      end

   end
end
