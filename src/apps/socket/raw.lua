-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local S = require("syscall")
local h = require("syscall.helpers")
local bit = require("bit")
local link = require("core.link")
local packet = require("core.packet")
local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local C = ffi.C

--ljsyscall returns error as a a cdata instead of a string,
--and the standard assert() doesn't use tostring() on it.
local function assert(v, ...)
   if not v then error(tostring(... or 'assertion failed'), 2) end
   return v, ...
end

local c, t = S.c, S.types.t

RawSocket = {}

local provided_counters = {
   'type', 'dtime',
   'rxbytes', 'rxpackets', 'rxmcast', 'rxbcast',
   'txbytes', 'txpackets', 'txmcast', 'txbcast'
}

function RawSocket:new (ifname)
   assert(ifname)
   local index, err = S.util.if_nametoindex(ifname)
   if not index then error(err) end

   local tp = h.htons(c.ETH_P["ALL"])
   local sock = assert(S.socket(c.AF.PACKET, bit.bor(c.SOCK.RAW, c.SOCK.NONBLOCK), tp))
   local index, err = S.util.if_nametoindex(ifname)
   if not index then
      sock:close()
      error(err)
   end

   local addr = t.sockaddr_ll{sll_family = c.AF.PACKET, sll_ifindex = index, sll_protocol = tp}
   local ok, err = S.bind(sock, addr)
   if not ok then
      sock:close()
      error(err)
   end
   local counters = {}
   for _, name in ipairs(provided_counters) do
      counters[name] = counter.open(name)
   end
   counter.set(counters.type, 0x1001) -- Virtual interface
   counter.set(counters.dtime, C.get_unix_time())
   return setmetatable({sock = sock,
                        rx_p = packet.allocate(),
                        counters = counters},
                       {__index = RawSocket})
end

function RawSocket:pull ()
   local l = self.output.tx
   if l == nil then return end
   while not link.full(l) and self:can_receive() do
      link.transmit(l, self:receive())
   end
end

function RawSocket:can_receive ()
   local t, err = S.select({readfds = {self.sock}}, 0)
   while not t and (err.AGAIN or err.INTR) do
      t, err = S.select({readfds = {self.sock}}, 0)
   end
   assert(t, err)
   return t.count == 1
end

function RawSocket:receive ()
   local p = self.rx_p
   local sz = assert(S.read(self.sock, p.data, packet.max_payload))
   p.length = sz
   counter.add(self.counters.rxbytes, sz)
   counter.add(self.counters.rxpackets)
   if ethernet:is_mcast(p.data) then
      counter.add(self.counters.rxmcast)
   end
   if ethernet:is_bcast(p.data) then
      counter.add(self.counters.rxbcast)
   end
   return packet.clone(p)
end

function RawSocket:push ()
   local l = self.input.rx
   if l == nil then return end
   while not link.empty(l) and self:can_transmit() do
      local p = link.receive(l)
      self:transmit(p)
      counter.add(self.counters.txbytes, p.length)
      counter.add(self.counters.txpackets)
      if ethernet:is_mcast(p.data) then
         counter.add(self.counters.txmcast)
      end
      if ethernet:is_bcast(p.data) then
         counter.add(self.counters.txbcast)
      end
      packet.free(p)
   end
end

function RawSocket:can_transmit ()
   local t, err = S.select({writefds = {self.sock}}, 0)
   while not t and (err.AGAIN or err.INTR) do
      t, err = S.select({writefds = {self.sock}}, 0)
   end
   assert(t, err)
   return t.count == 1
end

function RawSocket:transmit (p)
   local sz, err = S.write(self.sock, p.data, p.length)
   assert(sz, err)
   assert(sz == p.length)
end

function RawSocket:stop()
   self.sock:close()
   packet.free(self.rx_p)
   -- delete counters
   for name, _ in pairs(self.counters) do counter.delete(name) end
end

function selftest ()
   -- Send a packet over the loopback device and check
   -- that it is received correctly.
   local datagram = require("lib.protocol.datagram")
   local ethernet = require("lib.protocol.ethernet")
   local ipv6 = require("lib.protocol.ipv6")
   local Match = require("apps.test.match").Match

   -- Initialize RawSocket and Match.
   local c = config.new()
   config.app(c, "lo", RawSocket, "lo")
   config.app(c, "match", Match, {fuzzy=true})
   config.link(c, "lo.tx->match.rx")
   engine.configure(c)
   local link_in, link_cmp = link.new("test_in"), link.new("test_cmp")
   engine.app_table.lo.input.rx = link_in
   engine.app_table.match.input.comparator = link_cmp
   -- Construct packet.
   local dg_tx = datagram:new()
   local src = ethernet:pton("02:00:00:00:00:01")
   local dst = ethernet:pton("02:00:00:00:00:02")
   local localhost = ipv6:pton("0:0:0:0:0:0:0:1")
   dg_tx:push(ipv6:new({src = localhost,
                        dst = localhost,
                        next_header = 59, -- No next header.
                        hop_limit = 1}))
   dg_tx:push(ethernet:new({src = src,
                            dst = dst,
                            type = 0x86dd}))
   -- Transmit packets.
   link.transmit(link_in, dg_tx:packet())
   link.transmit(link_cmp, packet.clone(dg_tx:packet()))
   engine.app_table.lo:push()
   -- Run engine.
   engine.main({duration = 0.01, report = {showapps=true,showlinks=true}})
   assert(#engine.app_table.match:errors() == 0)
   print("selftest passed")

   -- XXX Another useful test would be to feed a pcap file with
   -- pings to 127.0.0.1 and ::1 into lo and capture/compare
   -- the responses with a pre-recorded pcap.
end
