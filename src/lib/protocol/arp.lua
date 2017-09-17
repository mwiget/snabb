module(..., package.seeall)
local ffi = require("ffi")
local header = require("lib.protocol.header")
local lib = require("core.lib")
local ntohs, htons = lib.ntohs, lib.htons

local arp = subClass(header)

-- Class variables
arp._name = "arp"
arp:init(
   {
      [1] = ffi.typeof[[
            struct {
               uint16_t hrd;
               uint16_t pro;
               uint8_t  hln;
               uint8_t  pln;
               uint16_t op;
            } __attribute__((packed))
      ]]
   })

arp.ETHERTYPE = 0x0806

arp.ETHERNET = 0x0001
arp.ETHERNET_ADDRESS_BYTES = 0x06

-- Class methods

function arp:new (config)
   local o = arp:superClass().new(self)
   o:pro(config.pro)
   o:pln(config.pln)
   o:op(config.op or 'request')
   -- default hardware address space is Ethernet
   o:hrd(config.hrd or arp.ETHERNET)
   o:hln(config.hln or arp.ETHERNET_ADDRESS_BYTES)
   return o
end

-- Instance methods

function arp:hrd (hrd)
   local h = self:header()
   if hrd ~= nil then
      h.hrd = htons(hrd)
   else
      return(ntohs(h.hrd))
   end
end

function arp:pro (pro)
   local h = self:header()
   if pro ~= nil then
      h.pro = htons(pro)
   else
      return(ntohs(h.pro))
   end
end

function arp:hln (hln)
   local h = self:header()
   if hln ~= nil then
      h.hln = hln
   else
      return(h.hln)
   end
end

function arp:pln (pln)
   local h = self:header()
   if pln ~= nil then
      h.pln = pln
   else
      return(h.pln)
   end
end

function arp:op (op)
   local h = self:header()
   if op ~= nil then
      if     op == 'request' then  h.op = htons(1)
      elseif op == 'reply'   then  h.op = htons(2)
      else error("Invalid op: "..op) end
   else
      return (ntohs(h.op) == 1 and 'request')
         or  (ntohs(h.op) == 2 and 'reply')
   end
end

return arp
