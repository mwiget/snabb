-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

-- This app implements a small subset of IPv6 neighbor discovery
-- (RFC4861).  It has two ports, north and south.  The south port
-- attaches to a port on which ND must be performed.  The north port
-- attaches to an app that processes IPv6 packets.  Packets
-- transmitted to and received from the north port contain full
-- Ethernet frames.
--
-- The app replies to neighbor solicitations for which it is
-- configured as target and performs rudimentary address resolution
-- for its configured "next-hop" address.  This is done by
-- transmitting a neighbor solicitation for the hext-hop with a
-- configurable number of retransmits (default 10) with a configurable
-- interval (default 1000ms) and processing the (solicited) neighbor
-- advertisements.
--
-- If address resolution succeeds, the app constructs an Ethernet
-- header with the discovered destination address, configured source
-- address and ethertype 0x86dd and overwrites the headers of all
-- packets received from the north port with it.  The resulting
-- packets are transmitted to the south port.  All packets from the
-- north port are discarded as long as ND has not yet succeeded.
--
-- Address resolution is not repeated for the lifetime of the app.
-- The app terminates if address resolution has not succeeded after
-- all retransmits have been performed.
--
-- Packets received from the south port are transmitted to the north
-- port unaltered, i.e. including the Ethernet header.

module(..., package.seeall)
local ffi = require("ffi")
local C = ffi.C
local app = require("core.app")
local link = require("core.link")
local config = require("core.config")
local packet = require("core.packet")
local datagram = require("lib.protocol.datagram")
local ethernet = require("lib.protocol.ethernet")
local ipv6 = require("lib.protocol.ipv6")
local icmp = require("lib.protocol.icmp.header")
local ns = require("lib.protocol.icmp.nd.ns")
local na = require("lib.protocol.icmp.nd.na")
local tlv = require("lib.protocol.icmp.nd.options.tlv")
local filter = require("lib.pcap.filter")
local timer = require("core.timer")
local lib = require("core.lib")

nd_light = subClass(nil)
nd_light._name = "Partial IPv6 neighbor discovery"

-- config:
--   local_mac  MAC address of the interface attached to "south".
--              Accepted formats:
--                6-byte on-the-wire representaion, either as a cdata
--                object (e.g. as returned by lib.protocol.ethernet:pton())
--                or a Lua string of lengh 6.
--
--                String with regular colon-notation.
--   local_ip   IPv6 address of the interface. Accepted formats:
--                16-byte on-the-wire representation, either as a cdata
--                object (e.g as returned by lib.protocol.ipv6:pton()) or
--                a Lus string of length 16.
--   next_hop   IPv6 address of next-hop for all packets to south.  Accepted
--              formats as for local_ip.
--   delay      NS retransmit delay in ms (default 1000ms)
--   retrans    Number of NS retransmits (default 10)
local function check_ip_address(ip, desc)
   assert(ip, "nd_light: missing "..desc.." IP address")
   if type(ip) == "string" and string.len(ip) ~= 16 then
      ip = ipv6:pton(ip)
   else
      assert(type(ip) == "cdata",
             "nd_light: invalid type of "..desc.." IP address, expected cdata, got "
                ..type(ip))
   end
   return ip
end

function nd_light:new (arg)
   local conf = arg and config.parse_app_arg(arg) or {}
   local o = nd_light:superClass().new(self)
   conf.delay = conf.delay or 1000
   conf.retrans = conf.retrans
   assert(conf.local_mac, "nd_light: missing local MAC address")
   if type(conf.local_mac) == "string" and string.len(conf.local_mac) ~= 6 then
      conf.local_mac = ethernet:pton(conf.local_mac)
   else
      assert(type(conf.local_mac) == "cdata",
             "nd_light: invalid type for local MAC address, expected cdata, got "
                ..type(conf.local_mac))
   end
   conf.local_ip = check_ip_address(conf.local_ip, "local")
   conf.next_hop = check_ip_address(conf.next_hop, "next-hop")

   o._config = conf
   o._match_ns = function(ns)
                    return(ns:target_eq(conf.local_ip))
                 end
   o._match_na = function(na)
                    return(na:target_eq(conf.next_hop) and na:solicited())
                 end
   local errmsg
   o._filter, errmsg = filter:new("icmp6 and ( ip6[40] = 135 or ip6[40] = 136 )")
   assert(o._filter, errmsg and ffi.string(errmsg))

   -- Prepare packet for solicitation of next hop
   local nh = { nsent = 0 }
   local dgram = datagram:new()
   nh.packet = dgram:packet()
   local sol_node_mcast = ipv6:solicited_node_mcast(conf.next_hop)
   local ipv6 = ipv6:new({ next_header = 58, -- ICMP6
         hop_limit = 255,
         src = conf.local_ip,
         dst = sol_node_mcast })
   local icmp = icmp:new(135, 0)

   -- Construct a neighbor solicitation with a source link-layer
   -- option.
   local ns = ns:new(conf.next_hop)
   local src_lladdr_tlv = tlv:new(1, conf.local_mac):tlv()
   local src_lladdr_tlv_len = ffi.sizeof(src_lladdr_tlv)
   -- We add both chunks to the payload rather than using push() for
   -- the ns header to have everything in a contiguous block for
   -- checksum calculation.
   dgram:payload(ns:header(), ns:sizeof())
   local mem, length = dgram:payload(src_lladdr_tlv, src_lladdr_tlv_len)
   icmp:checksum(mem, length, ipv6)
   dgram:push(icmp)
   ipv6:payload_length(icmp:sizeof() + ns:sizeof() + src_lladdr_tlv_len)
   dgram:push(ipv6)
   dgram:push(ethernet:new({ src = conf.local_mac,
                             dst = ethernet:ipv6_mcast(sol_node_mcast),
                             type = 0x86dd }))
   dgram:free()

   -- Timer for retransmits of neighbor solicitations
   nh.timer_cb = function (t)
                    local nh = o._next_hop
                    -- If nh.packet is nil the app was stopped and we
                    -- bail out.
                    if not nh.packet then return nil end
                    o._logger:log(string.format("Sending neighbor solicitation for next-hop %s",
                                                ipv6:ntop(conf.next_hop)))
                    link.transmit(o.output.south, packet.clone(nh.packet))
                    nh.nsent = nh.nsent + 1
                    if (not o._config.retrans or nh.nsent <= o._config.retrans)
                       and not o._eth_header
                    then
                       timer.activate(nh.timer)
                    end
                    if o._config.retrans and nh.nsent > o._config.retrans then
                       error(string.format("ND for next hop %s has failed",
                                           ipv6:ntop(conf.next_hop)))
                    end
                 end
   nh.timer = timer.new("ns retransmit", nh.timer_cb, 1e6 * conf.delay)
   o._next_hop = nh

   -- Prepare packet for solicited neighbor advertisement
   local sna = {}
   dgram = datagram:new()
   sna.packet = dgram:packet()
   -- Leave dst address unspecified.  It will be set to the source of
   -- the incoming solicitation
   ipv6 = ipv6:new({ next_header = 58, -- ICMP6
         hop_limit = 255,
         src = conf.local_ip })
   icmp = icmp:new(136, 0)
   -- Construct a neighbor solicitation with a target link-layer
   -- option.
   local na = na:new(conf.local_ip, nil, 1, nil)
   local tgt_lladdr_tlv = tlv:new(2, conf.local_mac):tlv()
   local tgt_lladdr_tlv_len = ffi.sizeof(tgt_lladdr_tlv)
   dgram:payload(na:header(), na:sizeof())
   local mem, length = dgram:payload(tgt_lladdr_tlv, tgt_lladdr_tlv_len)
   icmp:checksum(mem, length, ipv6)
   dgram:push(icmp)
   ipv6:payload_length(icmp:sizeof() + na:sizeof() + tgt_lladdr_tlv_len)
   dgram:push(ipv6)
   -- Leave dst address unspecified.
   dgram:push(ethernet:new({ src = conf.local_mac,
                             type = 0x86dd }))
   -- Parse the headers we want to modify later on from our template
   -- packet.
   dgram = dgram:new(sna.packet, ethernet)
   dgram:parse_n(3)
   sna.eth, sna.ipv6, sna.icmp = unpack(dgram:stack())
   sna.dgram = dgram
   o._sna = sna

   -- Caches for for various cdata pointer objects to avoid boxing in
   -- the push() loop
   o._cache = {
      p = ffi.new("struct packet *[1]"),
      mem = ffi.new("uint8_t *[1]")
   }
   o._logger = lib.logger_new({ module = 'nd_light' })
   return o
end

-- Process neighbor solicitation
local function ns (self, dgram, eth, ipv6, icmp)
   local mem, length = self._cache.mem
   mem[0], length = dgram:payload()
   if not icmp:checksum_check(mem[0], length, ipv6) then
      self._logger:log("bad icmp checksum")
      return nil
   end
   -- Parse the neighbor solicitation and check if it contains our own
   -- address as target
   local ns = dgram:parse_match(nil, self._match_ns)
   if not ns then
      return nil
   end
   -- Ignore options as long as we don't implement a proper neighbor
   -- cache.

   -- Set Ethernet and IPv6 destination addresses and re-compute the
   -- ICMP checksum
   local sna = self._sna
   sna.eth:dst(eth:src())
   sna.ipv6:dst(ipv6:src())
   -- The payload of the pre-fabricated packet consists of the NA and
   -- target ll-option
   mem[0], length = sna.dgram:payload()
   sna.icmp:checksum(mem[0], length, sna.ipv6)
   return true
end

-- Process neighbor advertisement
local function na (self, dgram, eth, ipv6, icmp)
   if self._eth_header then
      return nil
   end
   local na = dgram:parse_match(nil, self._match_na)
   if not na then
      return nil
   end
   local option = na:options(dgram:payload())
   if not (#option == 1 and option[1]:type() == 2) then
      -- Invalid NS, ignore
      return nil
   end
   self._eth_header = ethernet:new({ src = self._config.local_mac,
                                     dst = option[1]:option():addr(),
                                     type = 0x86dd })
   self._logger:log(string.format("Resolved next-hop %s to %s", ipv6:ntop(self._config.next_hop),
                                  ethernet:ntop(option[1]:option():addr())))
   return nil
end

local function from_south (self, p)
   if not self._filter:match(packet.data(p[0]), packet.length(p[0])) then
      return false
   end
   local dgram = datagram:new(p[0], ethernet)
   -- Parse the ethernet, ipv6 amd icmp headers
   dgram:parse_n(3)
   local eth, ipv6, icmp = unpack(dgram:stack())
   if ipv6:hop_limit() ~= 255 then
      -- Avoid off-link spoofing as per RFC
      return nil
   end
   local result
   if icmp:type() == 135 then
      result = ns(self, dgram, eth, ipv6, icmp)
   else
      result = na(self, dgram, eth, ipv6, icmp)
   end
   dgram:free()
   return result
end

function nd_light:push ()
   if self._next_hop.nsent == 0 then
      -- Kick off address resolution
      self._next_hop.timer_cb()
   end

   local cache = self._cache
   local l_in = self.input.south
   local l_out = self.output.north
   local l_reply = self.output.south
   while not link.empty(l_in) and not link.full(l_out) do
      local p = cache.p
      p[0] = link.receive(l_in)
      local status = from_south(self, p)
      if status == nil then
         -- Discard
         packet.free(p[0])
      elseif status == true then
         -- Send NA back south
         packet.free(p[0])
         link.transmit(l_reply, packet.clone(self._sna.packet))
      else
         -- Send transit traffic up north
         link.transmit(l_out, p[0])
      end
   end

   l_in = self.input.north
   l_out = self.output.south
   while not link.empty(l_in) and not link.full(l_out) do
      if not self._eth_header then
         -- Drop packets until ND for the next-hop
         -- has completed.
         packet.free(link.receive(l_in))
      else
         local p = cache.p
         p[0] = link.receive(l_in)
         if packet.length(p[0]) >= self._eth_header:sizeof() then
            self._eth_header:copy(packet.data(p[0]))
            link.transmit(l_out, p[0])
         else packet.free(p[0]) end
      end
   end
end

-- Free static packets on `stop'.
function nd_light:stop ()
   packet.free(self._next_hop.packet)
   self._next_hop.packet = nil
   packet.free(self._sna.packet)
   self._sna.packet = nil
end

function selftest ()
   local sink = require("apps.basic.basic_apps").Sink
   local c = config.new()
   config.app(c, "nd1", nd_light, { local_mac = "00:00:00:00:00:01",
                                    local_ip  = "2001:DB8::1",
                                    next_hop  = "2001:DB8::2" })
   config.app(c, "nd2", nd_light, { local_mac = "00:00:00:00:00:02",
                                    local_ip  = "2001:DB8::2",
                                    next_hop  = "2001:DB8::1" })
   config.app(c, "sink1", sink)
   config.app(c, "sink2", sink)
   config.link(c, "nd1.south -> nd2.south")
   config.link(c, "nd2.south -> nd1.south")
   config.link(c, "sink1.tx -> nd1.north")
   config.link(c, "nd1.north -> sink1.rx")
   config.link(c, "sink2.tx -> nd2.north")
   config.link(c, "nd2.north -> sink2.rx")
   engine.configure(c)
   engine.main({ duration = 2 })
   assert(engine.app_table.nd1._eth_header)
   assert(engine.app_table.nd2._eth_header)
end
