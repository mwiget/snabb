module(..., package.seeall)
local ffi = require("ffi")
local header = require("lib.protocol.header")

local arp_ipv4 = subClass(header)

-- Class variables
arp_ipv4._name = "arp_ipv4"
arp_ipv4:init(
   {
      [1] = ffi.typeof[[
            struct {
               uint8_t sha[6];
               uint8_t spa[4];
               uint8_t tha[6];
               uint8_t tpa[4];
            } __attribute__((packed))
      ]]
   })

arp_ipv4.PROTOCOL = 0x0800
arp_ipv4.ADDRESS_BYTES = 0x04

-- Class methods

function arp_ipv4:new (config)
   local o = arp_ipv4:superClass().new(self)
   -- default is Ethernet
   o:sha(config.sha)
   o:spa(config.spa)
   o:tha(config.tha)
   o:tpa(config.tpa)
   return o
end

-- Instance methods

function arp_ipv4:sha (sha)
   local h = self:header()
   if sha ~= nil then
      ffi.copy(h.sha, sha, 6)
   else
      return h.sha
   end
end

function arp_ipv4:spa (spa)
   local h = self:header()
   if spa ~= nil then
      ffi.copy(h.spa, spa, 4)
   else
      return h.spa
   end
end

function arp_ipv4:tha (tha)
   local h = self:header()
   if tha ~= nil then
      ffi.copy(h.tha, tha, 6)
   else
      return h.tha
   end
end

function arp_ipv4:tpa (tpa)
   local h = self:header()
   if tpa ~= nil then
      ffi.copy(h.tpa, tpa, 4)
   else
      return h.tpa
   end
end

return arp_ipv4
