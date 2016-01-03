-- Range maps -*- lua -*-
--
-- A range map is a map from uint32 to value.  It divides the space of
-- uint32 values into ranges, where every key in that range has the same
-- value.  The expectation is that you build a range map once and then
-- use it many times.  We also expect that the number of ranges ends up
-- being fairly small and will always be found in cache.  For this
-- reason, a lookup in the range map can use an optimized branchless
-- binary search.

module(..., package.seeall)

local ffi = require("ffi")
local C = ffi.C
local S = require('syscall')
local binary_search = require('apps.lwaftr.binary_search')

local UINT32_MAX = 0xFFFFFFFF

RangeMapBuilder = {}
RangeMap = {}

local function make_entry_type(value_type)
   return ffi.typeof([[struct {
         uint32_t key;
         $ value;
      } __attribute__((packed))]],
      value_type)
end

local function make_entries_type(entry_type)
   return ffi.typeof('$[?]', entry_type)
end

local function make_equal_fn(type)
   local size = ffi.sizeof(type)
   local cast = ffi.cast
   if tonumber(ffi.new(type)) then
      return function (a, b)
         return a == b
      end
   elseif size == 2 then
      local uint16_ptr_t = ffi.typeof('uint16_t*')
      return function (a, b)
         return cast(uint16_ptr_t, a)[0] == cast(uint16_ptr_t, b)[0]
      end
   elseif size == 4 then
      local uint32_ptr_t = ffi.typeof('uint32_t*')
      return function (a, b)
         return cast(uint32_ptr_t, a)[0] == cast(uint32_ptr_t, b)[0]
      end
   elseif size == 8 then
      local uint64_ptr_t = ffi.typeof('uint64_t*')
      return function (a, b)
         return cast(uint64_ptr_t, a)[0] == cast(uint64_ptr_t, b)[0]
      end
   else
      return function (a, b)
         return C.memcmp(a, b, size) == 0
      end
   end
end

function RangeMapBuilder.new(value_type, mtime_sec, mtime_nsec)
   local builder = {}
   builder.value_type = value_type
   builder.entry_type = make_entry_type(builder.value_type)
   builder.type = make_entries_type(builder.entry_type)
   builder.equal_fn = make_equal_fn(builder.value_type)
   builder.mtime_sec = mtime_sec or 0
   builder.mtime_nsec = mtime_nsec or 0
   builder.entries = {}
   builder = setmetatable(builder, { __index = RangeMapBuilder })
   return builder
end

function RangeMapBuilder:add_range(key_min, key_max, value)
   assert(key_min <= key_max)
   local min, max = ffi.new(self.entry_type), ffi.new(self.entry_type)
   min.key, min.value = key_min, value
   max.key, max.value = key_max, value
   table.insert(self.entries, { min=min, max=max })
end

function RangeMapBuilder:add(key, value)
   self:add_range(key, key, value)
end

function RangeMapBuilder:build()
   table.sort(self.entries, function(a,b) return a.max.key < b.max.key end)

   -- The optimized binary search routines in binary_search.dasl want to
   -- search for the entry whose key is *greater* than or equal to the K
   -- we are looking for.  Therefore we partition the range into
   -- contiguous entries with the highest K having a value V, starting
   -- with UINT32_MAX and working our way down.
   local ranges = {}
   if #self.entries == 0 then error('empty range map') end
   do
      local last_entry = ffi.new(self.entry_type)
      last_entry.key = UINT32_MAX
      last_entry.value = self.entries[#self.entries].max.value
      table.insert(ranges, last_entry)
   end
   local range_end = self.entries[#self.entries].min
   for i=#self.entries-1,1,-1 do
      local entry = self.entries[i]
      -- FIXME: We are using range maps for the address maps, but
      -- currently are specifying these parameters in the binding table
      -- where naturally one IPv4 address appears multiple times.  When
      -- we switch to a separate address map, we can assert that ranges
      -- are disjoint.  Until then, just assert that if ranges overlap
      -- that they have the same value.
      -- if entry.max.key >= range_end.key then
      --    error("Multiple range map entries for key: "..entry.max.key)
      -- end
      if not self.equal_fn(entry.max.value, range_end.value) then
         -- Remove this when the above test is enabled.
         if entry.max.key >= range_end.key then
            error("Key maps to multiple values: "..entry.max.key)
         end
         table.insert(ranges, entry.max)
         range_end = entry.min
      end
   end

   local range_count = #ranges
   local packed_entries = self.type(range_count)
   for i,entry in ipairs(ranges) do
      packed_entries[range_count-i] = entry
   end

   local map = {
      value_type = self.value_type,
      entry_type = self.entry_type,
      type = self.type,
      entries = packed_entries,
      size = range_count,
      mtime_sec = self.mtime_sec,
      mtime_nsec = self.mtime_nsec
   }
   map.binary_search = binary_search.gen(map.size, map.entry_type)
   map = setmetatable(map, { __index = RangeMap })
   return map
end

function RangeMap:lookup(k)
   return self.binary_search(self.entries, k)
end

local range_map_header_t = ffi.typeof[[
struct {
   uint8_t magic[8];
   uint32_t size;
   uint32_t entry_size;
   uint64_t mtime_sec;
   uint32_t mtime_nsec;
}
]]

local function round_up(x, y) return y*math.ceil(x/y) end

function RangeMap:save(filename)
   local fd, err = S.open(filename, "creat, wronly, trunc", "rusr, wusr, rgrp, roth")
   if not fd then
      error("error saving range map, while creating "..filename..": "..tostring(err))
   end
   local function write(ptr, size)
      ptr = ffi.cast("uint8_t*", ptr)
      local to_write = size
      while to_write > 0 do
         local written, err = S.write(fd, ptr, to_write)
         if not written then return size - to_write, err end
         ptr = ptr + written
         to_write = to_write - written
      end
      return size, nil
   end
   local entry_size = ffi.sizeof(self.entry_type)
   local header = range_map_header_t("rangemap", self.size, entry_size,
                                     self.mtime_sec, self.mtime_nsec)
   local header_size = ffi.sizeof(range_map_header_t)
   local written, err = write(header, header_size)
   if written then
      local padding = header_size - round_up(header_size, entry_size)
      written, err = write(string.rep(' ', padding), padding)
   end
   if written then
      local size = ffi.sizeof(self.type, self.size)
      written, err = write(self.entries, size)
   end
   fd:close()
   if err then error("error writing "..filename..": "..tostring(err)) end
end

function RangeMap.has_magic(filename)
   local fd, err = S.open(filename, "rdonly")
   if not fd then return false end
   local buf = ffi.new('uint8_t[9]')
   fd:read(buf, 8)
   local magic = ffi.string(buf)
   -- This function introduces a TOCTTOU situation, but that isn't
   -- terrible; we call this function just to know if the file exists
   -- and might be a compiled file.  We re-do these checks later in
   -- RangeMap.load().
   fd:close()
   return magic == 'rangemap'
end

function RangeMap.load(filename, value_type)
   local map = {}
   map.value_type = value_type
   map.entry_type = make_entry_type(map.value_type)
   map.type = make_entries_type(map.entry_type)

   local fd, err = S.open(filename, "rdonly")
   if not fd then
      error("error opening saved range map ("..filename.."): "..tostring(err))
   end
   local header_size = ffi.sizeof(range_map_header_t)
   local byte_size = S.fstat(fd).size
   if byte_size < header_size then
      fd:close()
      error("corrupted saved range map ("..filename.."): too short")
   end
   local mem, err = S.mmap(nil, byte_size, 'read, write', 'private', fd, 0)
   fd:close()
   if not mem then error("mmap failed: " .. tostring(err)) end
   local header = ffi.cast(ffi.typeof('$*', range_map_header_t), mem)
   local magic = ffi.string(header.magic, 8)
   if magic ~= "rangemap" then
      error("corrupted saved range map ("..filename.."): bad magic: "..magic)
   end
   local size = header.size
   local entry_size = header.entry_size
   if entry_size ~= ffi.sizeof(map.entry_type) then
      error("corrupted saved range map ("..filename.."): bad entry size: "..entry_size)
   end
   local offset = round_up(ffi.sizeof(range_map_header_t), entry_size)
   if byte_size ~= offset + entry_size*size then
      error("corrupted saved range map ("..filename.."): bad size: "..byte_size)
   end

   -- OK!
   map.entries = ffi.cast(ffi.typeof('$*', map.entry_type),
                          ffi.cast('uint8_t*', mem) + offset)
   map.size = size
   map.binary_search = binary_search.gen(map.size, map.entry_type)
   map.mtime_sec = header.mtime_sec
   map.mtime_nsec = header.mtime_nsec
   map = setmetatable(map, { __index = RangeMap })

   ffi.gc(map.entries, function () S.munmap(mem, size) end)

   return map
end

function selftest()
   local builder = RangeMapBuilder.new(ffi.typeof('uint8_t'))
   builder:add(0, 1)
   builder:add(1, 2)
   builder:add(100, 10)
   builder:add(101, 20)
   builder:add(200, 30)
   builder:add(300, 40)
   builder:add(301, 50)
   builder:add(302, 60)
   builder:add(350, 70)
   builder:add(370, 70)
   builder:add(400, 70)
   builder:add(401, 80)
   builder:add(UINT32_MAX-1, 99)
   builder:add(UINT32_MAX, 100)
   local map = builder:build()

   assert(map.size == 12)
   assert(map:lookup(0).value == 1)
   assert(map:lookup(1).value == 2)
   assert(map:lookup(2).value == 10)
   assert(map:lookup(99).value == 10)
   assert(map:lookup(100).value == 10)
   assert(map:lookup(101).value == 20)
   assert(map:lookup(102).value == 30)
   assert(map:lookup(199).value == 30)
   assert(map:lookup(200).value == 30)
   assert(map:lookup(201).value == 40)
   assert(map:lookup(300).value == 40)
   assert(map:lookup(301).value == 50)
   assert(map:lookup(302).value == 60)
   assert(map:lookup(303).value == 70)
   assert(map:lookup(349).value == 70)
   assert(map:lookup(350).value == 70)
   assert(map:lookup(399).value == 70)
   assert(map:lookup(400).value == 70)
   assert(map:lookup(401).value == 80)
   assert(map:lookup(402).value == 99)
   assert(map:lookup(UINT32_MAX-2).value == 99)
   assert(map:lookup(UINT32_MAX-1).value == 99)
   assert(map:lookup(UINT32_MAX).value == 100)

   local pmu = require('lib.pmu')
   local has_pmu_counters, err = pmu.is_available()
   if not has_pmu_counters then
      print('No PMU available: '..err)
   end

   if has_pmu_counters then pmu.setup() end

   local function measure(f, iterations)
      local set
      if has_pmu_counters then set = pmu.new_counter_set() end
      local start = C.get_time_ns()
      if has_pmu_counters then pmu.switch_to(set) end
      local res = f(iterations)
      if has_pmu_counters then pmu.switch_to(nil) end
      local stop = C.get_time_ns()
      local ns = tonumber(stop-start)
      local cycles = nil
      if has_pmu_counters then cycles = pmu.to_table(set).cycles end
      return cycles, ns, res
   end

   local function check_perf(f, iterations, max_cycles, max_ns, what)
      require('jit').flush()
      io.write(tostring(what or f)..': ')
      io.flush()
      local cycles, ns, res = measure(f, iterations)
      if cycles then
         cycles = cycles/iterations
         io.write(('%.2f cycles, '):format(cycles))
      end
      ns = ns/iterations
      io.write(('%.2f ns per iteration (result: %s)\n'):format(
            ns, tostring(res)))
      if cycles and cycles > max_cycles then
         print('WARNING: perfmark failed: exceeded maximum cycles '..max_cycles)
      end
      if ns > max_ns then
         print('WARNING: perfmark failed: exceeded maximum ns '..max_ns)
      end
      return res
   end

   local function test_lookup(iterations)
      local inc = math.floor(UINT32_MAX / iterations)
      local result = 0
      for i=0,UINT32_MAX,inc do result = map:lookup(i).value end
      return result
   end

   check_perf(test_lookup, 1e8, 35, 10, 'lookup')
end
