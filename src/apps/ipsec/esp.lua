-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

-- This app implements a point-to-point encryption tunnel using ESP with
-- AES-128-GCM.

module(..., package.seeall)
local esp = require("lib.ipsec.esp")
local counter = require("core.counter")
local C = require("ffi").C

AES128gcm = {}

local provided_counters = {
   'type', 'dtime', 'txerrors', 'rxerrors'
}

function AES128gcm:new (arg)
   local conf = arg and config.parse_app_arg(arg) or {}
   local self = {}
   self.encrypt = esp.esp_v6_encrypt:new{
      mode = "aes-128-gcm",
      spi = conf.spi,
      keymat = conf.key:sub(1, 32),
      salt = conf.key:sub(33, 40)}
   self.decrypt = esp.esp_v6_decrypt:new{
      mode = "aes-128-gcm",
      spi = conf.spi,
      keymat = conf.key:sub(1, 32),
      salt = conf.key:sub(33, 40),
      window_size = conf.replay_window}
   self.counters = {}
   for _, name in ipairs(provided_counters) do
      self.counters[name] = counter.open(name)
   end
   counter.set(self.counters.type, 0x1001) -- Virtual interface
   counter.set(self.counters.dtime, C.get_unix_time())
   return setmetatable(self, {__index = AES128gcm})
end

function AES128gcm:push ()
   -- Encapsulation path
   local input = self.input.decapsulated
   local output = self.output.encapsulated
   for _=1,link.nreadable(input) do
      local p = link.receive(input)
      if self.encrypt:encapsulate(p) then
         link.transmit(output, p)
      else
         packet.free(p)
         counter.add(self.counters.txerrors)
      end
   end
   -- Decapsulation path
   local input = self.input.encapsulated
   local output = self.output.decapsulated
   for _=1,link.nreadable(input) do
      local p = link.receive(input)
      if self.decrypt:decapsulate(p) then
         link.transmit(output, p)
      else
         packet.free(p)
         counter.add(self.counters.rxerrors)
      end
   end
end

function AES128gcm:stop ()
   -- delete counters
   for name, _ in pairs(self.counters) do counter.delete(name) end
end
