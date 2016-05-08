module(..., package.seeall)

local ffi = require("ffi")
local lib = require("core.lib")
local shm = require("core.shm")
local syscall = require("syscall")
local ethernet = require("lib.protocol.ethernet")
local S          = require("syscall")
local usage = require("program.snabbvmx.nexthop.README_inc")

local long_opts = {
   help = "h"
}

local function file_exists(path)
   local stat = S.stat(path)
   return stat and stat.isreg
end


function run (args)

  local opt = {}
  function opt.h (arg) print(usage) main.exit(1) end
  args = lib.dogetopt(args, opt, "h", long_opts)

  for _, pid in ipairs(shm.children("//")) do
    local pid_value = tonumber(pid)
    if pid_value and pid_value ~= syscall.getpid() then
      if not syscall.kill(pid_value, 0) then
        shm.unlink("//"..pid)
      else
--        print("pid " .. pid .. " type is " .. type(pid))
        local nh_v4_path = "//" .. pid .. "/next_hop_mac_v4"
        if file_exists("/var/run/snabb" .. nh_v4_path) then
           local nh_v4 = shm.open(nh_v4_path, "struct { uint8_t ether[6]; }", true)
           print(string.format("%d: next_hop_mac for IPv4 is %s", pid, ethernet:ntop(nh_v4.ether)))
           shm.unmap(nh_v4)
        end
        local nh_v6_path = "//" .. pid .. "/next_hop_mac_v6"
        if file_exists("/var/run/snabb" .. nh_v6_path) then
           local nh_v6 = shm.open(nh_v6_path, "struct { uint8_t ether[6]; }", true)
           print(string.format("%d: next_hop_mac for IPv6 is %s", pid, ethernet:ntop(nh_v6.ether)))
           shm.unmap(nh_v6)
        end
     end
    end
  end

end

