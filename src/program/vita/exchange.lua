-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(...,package.seeall)

local S = require("syscall")
local ffi = require("ffi")
local shm = require("core.shm")
local lib = require("core.lib")
local ipv4 = require("lib.protocol.ipv4")
local logger = lib.logger_new({ rate = 32, module = 'KeyManager' })

PROTOCOL = 99 -- “Any private encryption scheme”

KeyManager = {
   name = "KeyManager",
   config = {
      node_ip4 = {required=true},
      routes = {required=true},
      esp_keyfile = {required=true},
      dsp_keyfile = {required=true},
      negotiation_ttl = {default=10},
      sa_ttl = {default=(7 * 24 * 60 * 60)}
   }
}

local status = { expired = 0, negotiating = 1, ready = 2 }

function KeyManager:new (conf)
   local o = {
      node_ip4n = ipv4:pton(conf.node_ip4),
      routes = {},
      esp_keyfile = shm.root.."/"..shm.resolve(conf.esp_keyfile),
      dsp_keyfile = shm.root.."/"..shm.resolve(conf.dsp_keyfile),
      negotiation_ttl = conf.negotiation_ttl,
      sa_ttl = conf.sa_ttl,
      ip = ipv4:new({})
   }
   for _, route in ipairs(conf.routes) do
      o.routes[#o.routes+1] = {
         gw_ip4 = route.gw_ip4,
         gw_ip4n = ipv4:pton(route.gw_ip4), -- for fast compare
         preshared_key = lib.hexundump(route.preshared_key, 512),
         status = status.expired,
         tx_sa = nil, rx_sa = nil,
         timeout = nil
      }
   end
   return setmetatable(o, { __index = KeyManager })
end

function KeyManager:push ()
   local input = self.input.input
   for _=1,link.nreadable(input) do
      local request = link.receive(input)
      self:handle_negotiation(request)
      packet.free(request)
   end
   for _, route in ipairs(self.routes) do
      if route.status == status.expired then
         self:negotiate(route)
      end
   end
end

--[[
function KeyManager:reconfig ()
   -- TODO: reconfigure without clobbering SAs
end
]]--

function KeyManager:negotiate (route)
   logger:log("Sending key exchange request to "..route.gw_ip4)

   route.status = status.negotiating
   self:set_negotiation_timeout(route)

   route.tx_sa = { -- TODO: generate random SPI, key, and salt
      mode = "aes-gcm-128-12",
      spi = 0x0,
      key = "00112233445566778899AABBCCDDEEFF",
      salt = "00112233"
   }

   link.transmit(self.output.output, self:request(route))
end

function KeyManager:handle_negotiation (request)
   local route, sa = self:parse_request(request)
   if not route then
      logger:log("Ignoring malformed key exchange request")
      return
   end

   logger:log("Received key exchange request from "..route.gw_ip4)

   route.rx_sa = sa

   if route.status == status.negotiating then
      logger:log("Completed key exchange with "..route.gw_ip4)
      route.status = status.ready
      timer.deactivate(route.timeout)
      self:set_sa_timeout(route)
      self:commit_ephemeral_keys()
   else
      self:negotiate(route)
   end
end

function KeyManager:set_negotiation_timeout (route)
   route.timeout = timer.new(
      "negotiation_ttl",
      function ()
         logger:log("Expiring keys for "..route.gw_ip4.." (negotiation_ttl)")
         self:expire_route(route)
      end,
      self.negotiation_ttl * 1e9
   )
   timer.activate(route.timeout)
end

function KeyManager:set_sa_timeout (route)
   route.timeout = timer.new(
      "sa_ttl",
      function ()
         logger:log("Expiring keys for "..route.gw_ip4.." (sa_ttl)")
         self:expire_route(route)
      end,
      self.sa_ttl * 1e9
   )
   timer.activate(route.timeout)
end

function KeyManager:expire_route (route)
   route.status = status.expired
   route.tx_sa = nil
   route.rx_sa = nil
   route.timeout = nil
   self:commit_ephemeral_keys()
end

local request_t = ffi.typeof([[struct {
  uint32_t spi;
  uint8_t key[16];
  uint8_t salt[4];
} __attribute__((packed))]])

local request_t_ptr_t = ffi.typeof("$*", request_t)
local request_t_length = ffi.sizeof(request_t)

local request_trailer_t = ffi.typeof([[struct {
  uint8_t icv[12];
} __attribute__((packed))]])

local request_trailer_t_ptr_t = ffi.typeof("$*", request_trailer_t)
local request_trailer_t_length = ffi.sizeof(request_trailer_t)

local request_length =
   ipv4:sizeof() + request_t_length + request_trailer_t_length

function KeyManager:request (route)
   local request = packet.allocate()

   self.ip:new({
         total_length = request_length,
         ttl = 64,
         protocol = PROTOCOL,
         src = self.node_ip4n,
         dst = route.gw_ip4n
   })
   packet.append(request, self.ip:header(), ipv4:sizeof())

   packet.resize(request, request_length)

   local body = ffi.cast(request_t_ptr_t, request.data + ipv4:sizeof())
   body.spi = lib.htonl(route.tx_sa.spi)
   ffi.copy(body.key, lib.hexundump(route.tx_sa.key, 16), 16)
   ffi.copy(body.salt, lib.hexundump(route.tx_sa.salt, 4), 4)

   local trailer = ffi.cast(request_trailer_t_ptr_t,
                            request.data + ipv4:sizeof() + request_t_length)
   -- TODO: compute integrity check value including IP src and dst, and copy it
   -- it to trailer.icv

   -- TODO: encrypt body using route.preshared_key

   return request
end

function KeyManager:parse_request (request)
   if request.length ~= request_length then return end

   self.ip:new_from_mem(request.data, ipv4:sizeof())
   if self.ip:protocol() ~= PROTOCOL or not self.ip:dst_eq(self.node_ip4n) then
      return
   end

   local route = nil
   for _, r in ipairs(self.routes) do
      if self.ip:src_eq(r.gw_ip4n) then
         route = r
         break
      end
   end
   if not route then return end

   -- TODO: decrypt body using route.preshared_key

   local trailer = ffi.cast(request_trailer_t_ptr_t,
                            request.data + ipv4:sizeof() + request_t_length)
   -- TODO: authenticate request by verifying trailer.icv

   local function hexdump (bytes, n)
      local s = ""
      for i = 0, n - 1 do s = s..("%02X"):format(bytes[i]) end
      return s
   end

   local body = ffi.cast(request_t_ptr_t, request.data + ipv4:sizeof())
   local sa = {
      mode = "aes-gcm-128-12",
      spi = lib.ntohl(body.spi),
      key = hexdump(body.key, 16),
      salt = hexdump(body.salt, 4)
   }

   return route, sa
end

-- ephemeral_keys := { { gw_ip4=(IPv4), [ sa=(SA) ] }, ... }
function KeyManager:commit_ephemeral_keys ()
   local esp_conf, dsp_conf = {}, {}
   for _, route in ipairs(self.routes) do
      esp_conf[#esp_conf+1] = {
         gw_ip4 = route.gw_ip4,
         sa = (route.status == status.ready) and route.tx_sa
      }
      dsp_conf[#dsp_conf+1] = {
         gw_ip4 = route.gw_ip4,
         sa = (route.status == status.ready) and route.rx_sa
      }
   end
   lib.store_conf(self.esp_keyfile, esp_conf)
   lib.store_conf(self.dsp_keyfile, dsp_conf)
end
