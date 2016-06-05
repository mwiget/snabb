module(..., package.seeall)

local engine      = require("core.app")
local main        = require("core.main")
local timer       = require("core.timer")
local lib         = require("core.lib")
local config      = require("core.config")
local S           = require("syscall")
local pcap        = require("apps.pcap.pcap")
local lib         = require("core.lib")
local ffi = require("ffi")
local ipv6 = require("lib.protocol.ipv6")
local ethernet = require("lib.protocol.ethernet")
local C = ffi.C

--local usage = require("program.swapipv6.README_inc")

local long_opts = {
   read     = "r",   -- read pcap file as input
   write    = "w",   -- write pcap file for output
   help     = "h" 
}

local o_ethertype_ipv6 = C.htons(0x86DD)

local ipv6_header_t = ffi.typeof[[
struct {
   // ethernet
   uint8_t  ether_dhost[6];
   uint8_t  ether_shost[6];
   uint16_t ether_type;
   // ipv6
   uint32_t v_tc_fl; // version, tc, flow_label
   uint16_t payload_length;
   uint8_t  next_header;
   uint8_t hop_limit;
   uint8_t src_ip[16];
   uint8_t dst_ip[16];
   // tunnel
   uint32_t session_id;
   uint64_t cookie;
} __attribute__((packed))
]]
local ipv6_header_ptr_type = ffi.typeof("$*", ipv6_header_t)
local ipv6_header_size = ffi.sizeof(ipv6_header_t)

SwapV6 = {}

function SwapV6:new ()
   return setmetatable({}, {__index=SwapV6})
end

local receive, transmit = link.receive, link.transmit
local n_cache_ipv6 = ipv6:pton("::")
local n_cache_mac =  ethernet:pton("00:00:00:00:00:00")

function SwapV6:push ()

   local input = self.input.input
   local output = self.output.output


   for _=1, link.nreadable(input) do
      local pkt = receive(input) 
      local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data)
      if ipv6_hdr.ether_type == o_ethertype_ipv6 then
         ffi.copy(n_cache_mac, ipv6_hdr.ether_shost, 6)
         ffi.copy(ipv6_hdr.ether_shost, ipv6_hdr.ether_dhost, 6)
         ffi.copy(ipv6_hdr.ether_dhost, n_cache_mac, 6)
         ffi.copy(n_cache_ipv6, ipv6_hdr.src_ip, 16)
         ffi.copy(ipv6_hdr.src_ip, ipv6_hdr.dst_ip, 16)
         ffi.copy(ipv6_hdr.dst_ip, n_cache_ipv6, 16)
         transmit(output, pkt)
      end
   end

end

local function show_usage(exit_code)
--   print(require("program.swapipv6.README_inc"))
   print(require("program.snabbvmx.README_inc"))
   main.exit(exit_code)
end

local function file_exists(path)
   local stat = S.stat(path)
   return stat and stat.isreg
end

function run (args)
   local opt = {}
   local c = config.new()

   if #args == 0 then show_usage(1) end

   function opt.h (arg)
      show_usage(1)
   end

   local pcap_read
   function opt.r (arg)
      pcap_read = arg
      if not file_exists(pcap_read) then
         print(string.format("pcap file %s doesn't exist", pcap_read))
         main.exit(1)
      end
      target = pcap_read
   end

   local pcap_write
   function opt.w (arg)
      pcap_write = arg
   end

   function opt.D (arg)
      opt.duration = assert(tonumber(arg), "duration must be a number")
   end

   args = lib.dogetopt(args, opt, "r:w:hD:", long_opts)

   local input, output

   if pcap_read and pcap_write then
      config.app(c, "read", pcap.PcapReader, pcap_read)
      output = "read.output"
      config.app(c, "write", pcap.PcapWriter, pcap_write)
      input = "write.input"
   end

   config.app(c, "swap", SwapV6)

   config.link(c, "read.output -> swap.input")
   config.link(c, "swap.output -> write.input")

   engine.configure(c)

   if opt.duration then
      engine.main({duration=opt.duration})
   else
      engine.main()
   end
end
