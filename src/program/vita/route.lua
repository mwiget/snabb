-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(...,package.seeall)

local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local esp = require("lib.ipsec.esp")
local exchange = require("program.vita.exchange")
local lpm = require("lib.lpm.lpm4_248").LPM4_248
local ctable = require("lib.ctable")
local ffi = require("ffi")

-- route := { net_cidr4=(CIDR4), gw_ip4=(IPv4), preshared_key=(KEY) }

PrivateRouter = {
   name = "PrivateRouter",
   config = {
      routes = {required=true}
   }
}

function PrivateRouter:new (conf)
   local o = {
      routes = {},
      eth = ethernet:new({}),
      ip4 = ipv4:new({})
   }
   for _, route in ipairs(conf.routes) do
      o.routes[#o.routes+1] = {
         net_cidr4 = assert(route.net_cidr4, "Missing net_cidr4"),
         link = nil
      }
   end
   return setmetatable(o, {__index = PrivateRouter})
end

function PrivateRouter:link ()
   self.routing_table4 = lpm:new()
   for key, route in ipairs(self.routes) do
      route.link = self.output[config.link_name(route.net_cidr4)]
      self.routing_table4:add_string(route.net_cidr4, key)
   end
   self.routing_table4:build()
end

function PrivateRouter:find_route4 (dst)
   local route = self.routes[self.routing_table4:search_bytes(dst)]
   return route and route.link
end

function PrivateRouter:forward4 (p)
   local ip4 = self.ip4:new_from_mem(p.data, p.length)
   local route = ip4 and self:find_route4(ip4:dst())
   if route then
      link.transmit(route, p)
   else
      packet.free(p)
   end
end

function PrivateRouter:push ()
   local input = self.input.input
   for _=1,link.nreadable(input) do
      local p = link.receive(input)
      assert(self.eth:new_from_mem(p.data, p.length), "packet too short")
      if self.eth:type() == 0x0800 then
         self:forward4(packet.shiftleft(p, ethernet:sizeof()))
      else
         packet.free(p)
      end
   end
end


PublicRouter = {
   name = "PublicRouter",
   config = {
      routes = {required=true},
      node_ip4 = {required=true}
   }
}

function PublicRouter:new (conf)
   local o = {
      routes = {},
      eth = ethernet:new({}),
      ip4 = ipv4:new({})
   }
   for _, route in ipairs(conf.routes) do
      o.routes[#o.routes+1] = {
         gw_ip4 = assert(route.gw_ip4, "Missing gw_ip4"),
         link = nil
      }
   end
   return setmetatable(o, {__index = PublicRouter})
end

function PublicRouter:link ()
   local ipv4_addr_t = ffi.typeof("uint8_t[4]")
   local index_t = ffi.typeof("uint32_t")
   self.routing_table4 = ctable.new{
      key_type = ipv4_addr_t,
      value_type = index_t
   }
   for index, route in ipairs(self.routes) do
      assert(ffi.cast(index_t, index) == index, "index overflow")
      route.link = self.output[config.link_name(route.gw_ip4)]
      if route.link then
         self.routing_table4:add(ipv4:pton(route.gw_ip4), index)
      end
   end
end

function PublicRouter:find_route4 (src)
   return self.routes[self.routing_table4:lookup_ptr(src).value].link
end

function PublicRouter:forward4 (p)
   local ip4 = self.ip4:new_from_mem(p.data, p.length)
   if ip4 and ip4:protocol() == esp.PROTOCOL then
      local route = self:find_route4(self.ip4:src())
      if route then
         link.transmit(route, packet.shiftleft(p, ipv4:sizeof()))
      else
         packet.free(p)
      end
   elseif ip4 and ip4:protocol() == exchange.PROTOCOL then
      link.transmit(self.output.protocol, p)
   else
      packet.free(p)
   end
end

function PublicRouter:push ()
   local input = self.input.input
   for _=1,link.nreadable(input) do
      local p = link.receive(input)
      assert(self.eth:new_from_mem(p.data, p.length), "packet too short")
      if self.eth:type() == 0x0800 then
         self:forward4(packet.shiftleft(p, ethernet:sizeof()))
      else
         packet.free(p)
      end
   end
end
