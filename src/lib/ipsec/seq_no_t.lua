module(..., package.seeall)
local ffi = require("ffi")

-- Sequence number type with accessors for lower/upper order 32 bits

local seq_no_t = ffi.typeof("union { uint64_t no; uint32_t no32[2]; }")
local seq_no = {}

function seq_no:full () return self.no end

local low, high
if     ffi.abi("le") then low  = 0; high = 1
elseif ffi.abi("be") then low  = 1; high = 0 end

function seq_no:low (n)
   if n then self.no32[low] = n
   else return self.no32[low] end
end

function seq_no:high (n)
   if n then self.no32[high] = n
   else return self.no32[high] end
end

return ffi.metatype(seq_no_t, {__index=seq_no})
