-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local lib = require("core.lib")
local shm = require("core.shm")
local syscall = require("syscall")
local usage = require("program.gc.README_inc")

local long_opts = {
   help = "h"
}

function run (args)
   local opt = {}
   function opt.h (arg) print(usage) main.exit(1) end
   args = lib.dogetopt(args, opt, "h", long_opts)

   if #args > 0 then print(usage) main.exit(1) end

   -- Unlink stale snabb resources.
   for _, pid in ipairs(shm.children("//")) do
      if not syscall.kill(tonumber(pid), 0) then
         shm.unlink("//"..pid)
      end
   end
   -- Unlink own resource
   shm.unlink("//"..syscall.getpid())
end
