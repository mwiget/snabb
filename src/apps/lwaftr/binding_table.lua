module(..., package.seeall)

local ffi = require("ffi")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")

local binding_table = {
 {'127:2:3:4:5:6:7:128', '178.79.150.233', 1, 100},
 {'127:11:12:13:14:15:16:128', '178.79.150.233', 101, 100000}
}

local machine_friendly_binding_table

local function pton_binding_table(bt)
   local pbt = {}
   for _, v in ipairs(bt) do
      local pv6 = ipv6:pton(v[1])
      local pv4 = ffi.cast("uint32_t*", ipv4:pton(v[2]))[0]
      local pentry = {pv6, pv4, v[3], v[4]}
      table.insert(pbt, pentry)
   end
   return pbt
end

function get_binding_table()
   if not machine_friendly_binding_table then
      machine_friendly_binding_table = pton_binding_table(binding_table)
   end
   return machine_friendly_binding_table
end
