module(..., package.seeall)

local ffi = require("ffi")
local C = ffi.C
local lib = require("core.lib")
local shm = require("core.shm")
local syscall = require("syscall")
local counter = require("core.counter")
local S = require("syscall")
local usage = require("program.snabbvmx.top3.README_inc")

local long_opts = {
   help = "h"
}

local ifInDiscards_start

function clearterm () io.write('\027[2J') end

function run (args)
   local opt = {}
   function opt.h (arg) print(usage) main.exit(1) end
   args = lib.dogetopt(args, opt, "h", long_opts)

   if #args > 1 then print(usage) main.exit(1) end
   local target_pid = args[1]

   -- Unlink stale snabb resources.
   for _, pid in ipairs(shm.children("//")) do
     if not syscall.kill(tonumber(pid), 0) then
       shm.unlink("//"..pid)
     end
   end
      
   local instance_tree = "//"..(select_snabb_instance(target_pid))
   local counters = open_counters(instance_tree)
   local configs = 0
   local last_stats = nil
   local last_time = nil
   while (true) do
      local new_stats = get_stats(counters)
      local time = tonumber(C.get_time_ns())
      if last_stats then
         clearterm()
         print_l2tpv3_metrics(new_stats, last_stats, (time - last_time)/1000)
         io.flush()
      end
      last_stats = new_stats
      last_time = time
      C.sleep(1)
   end
end

function select_snabb_instance (pid)
   local instances = shm.children("//")
   if pid then
      -- Try to use given pid
      for _, instance in ipairs(instances) do
         if instance == pid then return pid end
      end
      print("No such Snabb Switch instance: "..pid)
   elseif #instances == 2 then
      -- Two means one is us, so we pick the other.
      local own_pid = tostring(S.getpid())
      if instances[1] == own_pid then return instances[2]
      else                            return instances[1] end
   elseif #instances == 1 then print("No Snabb Switch instance found.")
   else print("Multple Snabb Switch instances found. Select one.") end
   os.exit(1)
end

function open_counters (tree)
  local counters = {}
   counters.l2tpv3 = {}
   for _,l2tpv3spec in pairs({"l2tpv3_v6", "l2tpv3_nh", "l2tpv3_trunk"}) do
      counters.l2tpv3[l2tpv3spec] = {}
      if l2tpv3spec == "nic" then
        name = "ifInDiscards"
        counters.l2tpv3[l2tpv3spec][name] =
        counter.open(tree .. "/nic/ifInDiscards", 'readonly')
        ifInDiscards_start = counter.read(counters.l2tpv3[l2tpv3spec][name])
     elseif l2tpv3spec == "l2tpv3_nh" then
        for _, name
          in ipairs({"rcvdPacket", "sentPacket", "rcvdByte", "sentByte"}) do
          counters.l2tpv3[l2tpv3spec][name] =
          counter.open(tree .."/" .. l2tpv3spec .. "/" .. name, 'readonly')
        end
        
      else
        for _, name
          in ipairs({"rcvdPacket", "sentPacket", "rcvdByte", "sentByte", "droppedPacket",
          "bridgedPacket", "bridgedByte"}) do
          counters.l2tpv3[l2tpv3spec][name] =
          counter.open(tree .."/" .. l2tpv3spec .. "/" .. name, 'readonly')
        end
      end
   end
   return counters
end

function get_stats (counters)
   local new_stats = {}
   new_stats.l2tpv3 = {}
   for l2tpv3spec, l2tpv3 in pairs(counters.l2tpv3) do
      new_stats.l2tpv3[l2tpv3spec] = {}
      if l2tpv3spec == "nic" then
        name = "ifInDiscards"
        new_stats.l2tpv3[l2tpv3spec][name] = counter.read(l2tpv3[name])
      elseif l2tpv3spec == "l2tpv3_nh" then
        for _, name
          in ipairs({"rcvdPacket", "sentPacket", "rcvdByte", "sentByte" }) do
          new_stats.l2tpv3[l2tpv3spec][name] = counter.read(l2tpv3[name])
        end
      else
        for _, name
          in ipairs({"rcvdPacket", "sentPacket", "rcvdByte", "sentByte", "droppedPacket", "bridgedPacket", "bridgedByte" }) do
          new_stats.l2tpv3[l2tpv3spec][name] = counter.read(l2tpv3[name])
        end
      end
   end
   return new_stats
end

local l2tpv3_metrics_row = {31, 7, 7, 7, 7, 11}
function print_l2tpv3_metrics (new_stats, last_stats, time_delta)
   print_row(l2tpv3_metrics_row,
             {"l2tpv3 (rx/tx/txdrop in Mpps)", "rx", "tx", "rxGb", "txGb", "txdrop"})
   for l2tpv3spec, l2tpv3 in pairs(new_stats.l2tpv3) do
     if l2tpv3spec ~= "nic" then
      if last_stats.l2tpv3[l2tpv3spec] then
         local rx = tonumber(new_stats.l2tpv3[l2tpv3spec].rcvdPacket - last_stats.l2tpv3[l2tpv3spec].rcvdPacket)
         local tx = tonumber(new_stats.l2tpv3[l2tpv3spec].sentPacket - last_stats.l2tpv3[l2tpv3spec].sentPacket)
         local rxbytes = tonumber(new_stats.l2tpv3[l2tpv3spec].rcvdByte - last_stats.l2tpv3[l2tpv3spec].rcvdByte)
         local txbytes = tonumber(new_stats.l2tpv3[l2tpv3spec].sentByte - last_stats.l2tpv3[l2tpv3spec].sentByte)
         local drop = 0
         if new_stats.l2tpv3[l2tpv3spec].droppedPacket then
            drop = tonumber(new_stats.l2tpv3[l2tpv3spec].droppedPacket - last_stats.l2tpv3[l2tpv3spec].droppedPacket)
         end
         print_row(l2tpv3_metrics_row,
                   {l2tpv3spec,
                    float_s(rx / time_delta), float_s(tx / time_delta),
                    float_s(rxbytes / time_delta / 1000 *8), float_s(txbytes / time_delta / 1000 *8),
                    float_l(drop / time_delta)})
      end
     end
   end

   local metrics_row = {30, 20, 20}
   for l2tpv3spec, l2tpv3 in pairs(new_stats.l2tpv3) do
     if last_stats.l2tpv3[l2tpv3spec] then
        io.write(("\n%30s  %20s %20s\n"):format("", "Total", "per second"))
        if l2tpv3spec == "nic" then
          name = "ifInDiscards"
          local delta = tonumber(new_stats.l2tpv3[l2tpv3spec][name] - last_stats.l2tpv3[l2tpv3spec][name])
            print_row(metrics_row, {l2tpv3spec .. " " .. name,
            int_s(new_stats.l2tpv3[l2tpv3spec][name] - ifInDiscards_start), int_s(delta)})
        elseif l2tpv3spec == "l2tpv3_nh" then
          for _, name
            in ipairs({"rcvdPacket", "sentPacket", "rcvdByte", "sentByte" }) do
            local delta = tonumber(new_stats.l2tpv3[l2tpv3spec][name] - last_stats.l2tpv3[l2tpv3spec][name])
            print_row(metrics_row, {l2tpv3spec .. " " .. name,
            int_s(new_stats.l2tpv3[l2tpv3spec][name]), int_s(delta)})
          end
        else
          for _, name
            in ipairs({"rcvdPacket", "sentPacket", "rcvdByte", "sentByte", "droppedPacket", "bridgedPacket", "bridgedByte" }) do
            local delta = tonumber(new_stats.l2tpv3[l2tpv3spec][name] - last_stats.l2tpv3[l2tpv3spec][name])
            print_row(metrics_row, {l2tpv3spec .. " " .. name,
            int_s(new_stats.l2tpv3[l2tpv3spec][name]), int_s(delta)})
          end
        end
     end
   end
end

function pad_str (s, n)
   local padding = math.max(n - s:len(), 0)
   return ("%s%s"):format(s:sub(1, n), (" "):rep(padding))
end

function print_row (spec, args)
   for i, s in ipairs(args) do
      io.write((" %s"):format(pad_str(s, spec[i])))
   end
   io.write("\n")
end

function int_s (n)
   return ("%20d"):format(tonumber(n))
end

function float_s (n)
   return ("%.2f"):format(n)
end

function float_l (n)
   return ("%.6f"):format(n)
end
