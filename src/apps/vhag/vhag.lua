module(..., package.seeall)

local app = require("core.app")
local basic_apps = require("apps.basic.basic_apps")
local bit = require("bit")
local constants = require("apps.lwaftr.constants")
local ethernet = require("lib.protocol.ethernet")
local ipsum = require("lib.checksum").ipsum
local ipv4 = require("lib.protocol.ipv4")
local lib = require("core.lib")
local lwutil = require("apps.lwaftr.lwutil")
local shm = require("core.shm")

local ffi = require("ffi")
local C = ffi.C

local transmit, receive = link.transmit, link.receive
local ntohs, htons = lib.ntohs, lib.htons

local rd16, rd32, wr16, wr32  = lwutil.rd16, lwutil.rd32, lwutil.wr16, lwutil.wr32
local lshift, band = bit.lshift, bit.band

local gre4_header_t = ffi.typeof[[
struct {
  // ethernet
  uint8_t  ether_dhost[6];
  uint8_t  ether_shost[6];
  uint16_t ether_type;
  // ipv4
  uint16_t ihl_v_tos; // ihl:4, version:4, tos(dscp:6 + ecn:2)
  uint16_t total_length;
  uint16_t id;
  uint16_t frag_off; // flags:3, fragmen_offset:13
  uint8_t  ttl;
  uint8_t  ipv4_proto;
  uint16_t checksum;
  uint8_t  src_ip[4];
  uint8_t  dst_ip[4];
  // gre
  uint16_t gre_flags;
  uint16_t gre_proto;
} __attribute__((packed))
]]
local gre4_header_ptr_type = ffi.typeof("$*", gre4_header_t)
local gre4_header_size = ffi.sizeof(gre4_header_t)

local dhcp_header_t = ffi.typeof[[
struct {
  // ethernet
  uint8_t  ether_dhost[6];
  uint8_t  ether_shost[6];
  uint16_t ether_type;
  // ipv4
  uint16_t ihl_v_tos; // ihl:4, version:4, tos(dscp:6 + ecn:2)
  uint16_t total_length;
  uint16_t id;
  uint16_t frag_off; // flags:3, fragmen_offset:13
  uint8_t  ttl;
  uint8_t  ipv4_proto;
  uint16_t ip_checksum;
  uint8_t  src_ip[4];
  uint8_t  dst_ip[4];
  // udp
  uint16_t    src_port;
  uint16_t    dst_port;
  uint16_t    len;
  uint16_t    udp_checksum;
  // dhcp
  uint8_t     dhcp_msg_type;
  uint8_t     dhcp_hw_type;
  uint8_t     dhcp_hw_len;
  uint8_t     dhcp_hops;
  uint32_t    dhcp_transcation_id;
  uint16_t    dhcp_seconds_elapsed;
  uint16_t    dhcp_bootp_flags;
  uint8_t     dhcp_client_ip[4];
  uint8_t     dhcp_your_ip[4];
  uint8_t     dhcp_server_ip[4];
  uint8_t     dhcp_relay_ip[4];
  uint8_t     dhcp_client_mac[6];
  uint8_t     dhcp_padding[10];
  uint8_t     dhcp_server_host_name[64];
  uint8_t     dhcp_bootp_filename[128];
  uint32_t    dhcp_magic_cookie;
  uint8_t     dhcp_option;
  uint8_t     dhcp_option_len;
  uint8_t     dhcp_option_value;
} __attribute__((packed))
]]
local dhcp_header_ptr_type = ffi.typeof("$*", dhcp_header_t)
local dhcp_header_size = ffi.sizeof(dhcp_header_t)

local udp_dhcp_port = htons(67)
local ethernet_broadcast = ethernet:pton("ff:ff:ff:ff:ff:ff")
local ipv4_zero = ipv4:pton("0.0.0.0")
local ipv4_broadcast = ipv4:pton("255.255.255.255")

Vhag = {}

vhag = {
  mac_address = {required=true},
  fake_mac = {required=false, default=nil},
  ipv4_address = {required=true},
  debug = {default=false},
  cache_refresh_interval = {default=0},
  next_hop_mac = {required=false, default=nil}
}

local client_src_ip_table = {}
local client_src_mac_table = {}
local dhcp_client_mac_table = {}
local dhcp_relay_ip_table = {}

local ethernet_header_size = constants.ethernet_header_size
local n_ethertype_ipv4 = constants.n_ethertype_ipv4
local proto_ipv4 = constants.proto_ipv4
local o_ipv4_checksum = constants.o_ipv4_checksum
local o_ipv4_dst_addr = constants.o_ipv4_dst_addr
local o_ipv4_src_addr = constants.o_ipv4_src_addr
local o_ipv4_proto = constants.o_ipv4_proto

local n_cache_src_ipv4 = ipv4:pton("169.254.254.254")
local val_cache_src_ipv4 = rd32(n_cache_src_ipv4)
local n_next_hop_mac_empty = ethernet:pton("00:00:00:00:00:00")

local function get_ethertype(pkt)
   return rd16(pkt.data + (ethernet_header_size - 2))
end
local function get_ethernet_payload(pkt)
   return pkt.data + ethernet_header_size
end
local function get_ipv4_dst_address(ptr)
   return rd32(ptr + o_ipv4_dst_addr)
end
local function get_ipv4_proto(ptr)
   return ptr[o_ipv4_proto]
end
local function get_ipv4_src_ptr(ptr)
   return ptr + o_ipv4_src_addr
end
local function get_ipv4_src_address(ptr)
   return rd32(get_ipv4_src_ptr(ptr))
end
local function get_ipv4_checksum_ptr (ptr)
   return ptr + o_ipv4_checksum
end
local function get_ether_dhost_ptr (pkt)
   return pkt.data
end
local function ether_equals (dst, src)
   return C.memcmp(dst, src, 6) == 0
end
local function copy_ether(dst, src)
   ffi.copy(dst, src, 6)
end
local function copy_ipv4(dst, src)
   ffi.copy(dst, src, 4)
end
local function get_ipv4_header_length(ptr)
   local ver_and_ihl = ptr[0]
   return lshift(band(ver_and_ihl, 0xf), 2)
end

local function ipv4_cache_trigger (pkt, mac)
   local ether_dhost = get_ether_dhost_ptr(pkt)
   local ipv4_hdr = get_ethernet_payload(pkt)
   local ipv4_hdr_size = get_ipv4_header_length(ipv4_hdr)
   local ipv4_src_ip = get_ipv4_src_ptr(ipv4_hdr)
   local ipv4_checksum = get_ipv4_checksum_ptr(ipv4_hdr)

   -- VM will discard packets not matching its MAC address on the interface.
   copy_ether(ether_dhost, mac)

   -- Set a bogus source IP address.
   copy_ipv4(ipv4_src_ip, n_cache_src_ipv4)

   -- Clear checksum to recalculate it with new source IPv4 address.
   wr16(ipv4_checksum, 0)
   wr16(ipv4_checksum, htons(ipsum(pkt.data + ethernet_header_size, ipv4_hdr_size, 0)))

   return pkt
end

local function send_ipv4_cache_trigger (r, pkt, mac)
   transmit(r, ipv4_cache_trigger(pkt, mac))
end

function Vhag:new (conf)
   if not conf.ipv4_address then
     conf.ipv4_address = "0.0.0.0"
   end
   local ipv4_address = rd32(ipv4:pton(conf.ipv4_address))
   local debug = conf.debug
   local next_hop_mac = shm.create("next_hop_mac_v4", "struct { uint8_t ether[6]; }")
   local mac_address = ethernet:pton(conf.access.mac_address)
   print(("vhag: mac_address=%s"):format(ethernet:ntop(mac_address)))
   if conf.next_hop_mac then
      next_hop_mac = ethernet:pton(conf.next_hop_mac)
      print(("vhag: static next_hop_mac %s"):format(ethernet:ntop(next_hop_mac)))
    else
      next_hop_mac = ethernet:pton("00:00:00:00:00:00")
   end
   if conf.fake_mac then
      fake_mac = ethernet:pton(conf.fake_mac)
    else
      fake_mac = ethernet:pton("22:22:00:00:00:00")
   end
   print(("vhag: static fake_mac %s"):format(ethernet:ntop(fake_mac)))

   local o = {
      next_hop_mac = next_hop_mac,
      mac_address = mac_address,
      fake_mac = fake_mac,
      ipv4_address = ipv4_address,
      client_src_ip_table = client_src_ip_table,
      client_src_mac_table = client_src_mac_table,
      dhcp_client_mac_table = dhcp_client_mac_table,
      dhcp_relay_ip_table = dhcp_relay_ip_table,
      debug = conf.debug,
      cache_refresh_time = 0,
   }
   return setmetatable(o, {__index = Vhag})
end

function Vhag:push ()
   local input_access, output_access = self.input.access, self.output.access
   local input_trunk, output_trunk = self.input.trunk, self.output.trunk

   local mac_address = self.mac_address
   local fake_mac = self.fake_mac
   local current_time = tonumber(app.now())
   local ipv4_address = self.ipv4_address

   -- IPv4 from Access.
   if input_access then
     for _ = 1, link.nreadable(input_access) do
       local pkt = receive(input_access)
       --         local ipv4_hdr = get_ethernet_payload(pkt)
       --         local ipv4_proto = get_ipv4_proto(ipv4_hdr)
       local gre4_pkt = ffi.cast(gre4_header_ptr_type, pkt.data)

       if gre4_pkt.ether_type == n_ethertype_ipv4 
         and gre4_pkt.ipv4_proto == 47 and gre4_pkt.gre_proto == n_ethertype_ipv4 
         and rd32(gre4_pkt.dst_ip) == ipv4_address then

         local gre4_src_address = ipv4:pton("0.0.0.0")
         ffi.copy(gre4_src_address, gre4_pkt.src_ip, 4)
         ffi.copy(self.next_hop_mac, gre4_pkt.ether_shost, 6)

--         print(("GRE packet from %s"):format(ipv4:ntop(gre4_src_address)))
         pkt = packet.shiftleft(pkt, gre4_header_size - 14)
         local dhcp_pkt = ffi.cast(dhcp_header_ptr_type, pkt.data)
         ffi.copy(dhcp_pkt.ether_dhost, mac_address, 6)
         ffi.copy(dhcp_pkt.ether_shost + 2, gre4_src_address, 4)
--         print(("Generated client mac %s"):format(ethernet:ntop(dhcp_pkt.ether_shost)))
         local client_key = ffi.string(dhcp_pkt.ether_shost, 6)
         self.client_src_ip_table[client_key] = gre4_src_address

         if dhcp_pkt.ipv4_proto == 17 and dhcp_pkt.dst_port == udp_dhcp_port then
           if dhcp_pkt.dhcp_option == 53 then
             if dhcp_pkt.dhcp_option_value == 1 then 
--               print ("DHCP DISCOVER")

               ffi.copy(dhcp_pkt.ether_dhost, ethernet_broadcast, 6)
               ffi.copy(dhcp_pkt.src_ip, ipv4_zero, 4)
               dhcp_pkt.dhcp_hops = 0
               ffi.copy(dhcp_pkt.dst_ip, ipv4_broadcast, 4)
--               print(("orig dhcp_client_mac %s"):format(ethernet:ntop(dhcp_pkt.dhcp_client_mac)))
               local mac = ethernet:pton("00:00:00:00:00:00")
               ffi.copy(mac, dhcp_pkt.dhcp_client_mac, 6)
               self.client_src_mac_table[client_key] = mac
               local relay_ip = ipv4:pton("0.0.0.0")
               ffi.copy(relay_ip, dhcp_pkt.dhcp_relay_ip, 4)
               self.dhcp_relay_ip_table[client_key] = relay_ip
               ffi.copy(dhcp_pkt.dhcp_relay_ip, ipv4_zero, 4)
               ffi.copy(dhcp_pkt.dhcp_client_mac, dhcp_pkt.ether_shost, 6)
--               print(("new dhcp_client_mac %s"):format(ethernet:ntop(dhcp_pkt.dhcp_client_mac)))
               dhcp_pkt.src_port = htons(68)
               dhcp_pkt.udp_checksum = 0

            elseif dhcp_pkt.dhcp_option_value == 3 then -- REQUEST
 --              print ("DHCP REQUEST")
               ffi.copy(dhcp_pkt.ether_dhost, mac_address, 6)
               dhcp_pkt.dhcp_hops = 0
               ffi.copy(dhcp_pkt.dst_ip, ipv4_broadcast, 4)
  --             print(("orig dhcp_client_mac %s"):format(ethernet:ntop(dhcp_pkt.dhcp_client_mac)))
               local mac = ethernet:pton("00:00:00:00:00:00")
               ffi.copy(mac, dhcp_pkt.dhcp_client_mac, 6)
               self.client_src_mac_table[client_key] = mac
               local relay_ip = ipv4:pton("0.0.0.0")
               ffi.copy(relay_ip, dhcp_pkt.dhcp_relay_ip, 4)
               self.dhcp_relay_ip_table[client_key] = relay_ip
               ffi.copy(dhcp_pkt.dhcp_relay_ip, ipv4_zero, 4)
               ffi.copy(dhcp_pkt.dhcp_client_mac, dhcp_pkt.ether_shost, 6)
--               print(("new dhcp_client_mac %s"):format(ethernet:ntop(dhcp_pkt.dhcp_client_mac)))
               dhcp_pkt.src_port = htons(68)
               dhcp_pkt.udp_checksum = 0
             end

             local ipv4_hdr = get_ethernet_payload(pkt)
             local ipv4_hdr_size = get_ipv4_header_length(ipv4_hdr)
             local ipv4_checksum = get_ipv4_checksum_ptr(ipv4_hdr)
             -- Clear checksum to recalculate it with new source IPv4 address.
             wr16(ipv4_checksum, 0)
             wr16(ipv4_checksum, htons(ipsum(pkt.data + ethernet_header_size, ipv4_hdr_size, 0)))
           end
         end
       end
      transmit(output_trunk, pkt)
     end
   end

   -- IPv4 from Trunk.
   if input_trunk then
      for _ = 1, link.nreadable(input_trunk) do
         local pkt = receive(input_trunk)
         local dhcp_pkt = ffi.cast(dhcp_header_ptr_type, pkt.data)

         local client_key = ffi.string(dhcp_pkt.ether_dhost, 6)

         local gre4_src_address = self.client_src_ip_table[client_key]
         local dhcp_client_mac = self.client_src_mac_table[client_key]

         if gre4_src_address then

--           print(("Trunk dst mac %s ipv4_proto=%d udp port=%d"):format(ethernet:ntop(dhcp_pkt.ether_dhost), dhcp_pkt.ipv4_proto, ntohs(dhcp_pkt.dst_port)))

           if dhcp_pkt.ipv4_proto == 17 and dhcp_pkt.dst_port == htons(68) then
--             print("Trunk DHCP pkt")
              wr32(dhcp_pkt.src_ip, ipv4_address)
              ffi.copy(dhcp_pkt.dst_ip, gre4_src_address, 4)
              ffi.copy(dhcp_pkt.dhcp_relay_ip, self.dhcp_relay_ip_table[client_key], 4)
--              print(("set dhcp relay ip to %s"):format(ipv4:ntop(dhcp_pkt.dhcp_relay_ip)))
              if dhcp_client_mac then
--                print("dhcp_client_mac  found")
                ffi.copy(dhcp_pkt.dhcp_client_mac, dhcp_client_mac, 6)
              else
--                print("dhcp_client_mac not found")
              end
              dhcp_pkt.dst_port = htons(67)
              dhcp_pkt.dhcp_hops = 2
              dhcp_pkt.udp_checksum = 0
           end

           local ipv4_hdr = get_ethernet_payload(pkt)
           local ipv4_hdr_size = get_ipv4_header_length(ipv4_hdr)
           local ipv4_checksum = get_ipv4_checksum_ptr(ipv4_hdr)
           -- Clear checksum to recalculate it with new source IPv4 address.
           wr16(ipv4_checksum, 0)
           wr16(ipv4_checksum, htons(ipsum(pkt.data + ethernet_header_size, ipv4_hdr_size, 0)))

           local length = ntohs(dhcp_pkt.total_length)
           local ihl_v_tos = dhcp_pkt.ihl_v_tos

           pkt = packet.shiftright(pkt, gre4_header_size - 14)
 --          print(("packet shift right by %d packets"):format(gre4_header_size - 14))
           local gre4_pkt = ffi.cast(gre4_header_ptr_type, pkt.data)
           gre4_pkt.ether_type = n_ethertype_ipv4 
           gre4_pkt.total_length = htons(length + gre4_header_size - 14)
           gre4_pkt.ihl_v_tos = ihl_v_tos
           gre4_pkt.ipv4_proto = 47
           ffi.copy(gre4_pkt.ether_shost, mac_address, 6)
           ffi.copy(gre4_pkt.ether_dhost, self.next_hop_mac, 6)
           wr32(gre4_pkt.src_ip, ipv4_address)
           ffi.copy(gre4_pkt.dst_ip, gre4_src_address, 4)

           local ipv4_hdr = get_ethernet_payload(pkt)
           local ipv4_hdr_size = get_ipv4_header_length(ipv4_hdr)
           local ipv4_checksum = get_ipv4_checksum_ptr(ipv4_hdr)
           -- Clear checksum to recalculate it with new source IPv4 address.
           wr16(ipv4_checksum, 0)
           wr16(ipv4_checksum, htons(ipsum(pkt.data + ethernet_header_size, ipv4_hdr_size, 0)))
  --         print(("packet sent to %s"):format(ipv4:ntop(gre4_pkt.dst_ip)))

           transmit(output_access, pkt)

         else
--           print(("no GRE IP found in mac %s"):format(ethernet:ntop(dhcp_pkt.ether_dhost)))
           transmit(output_access, pkt)
         end

       end
   end
end


-- Unit tests.

local function transmit_packets (l, pkts)
   for _, pkt in ipairs(pkts) do
      link.transmit(l, packet.from_string(pkt))
   end
end

-- Test Wire to VM and Service.
local function test_ipv4_wire_to_vm_and_service (pkts)
   local c = config.new()
   config.app(c, 'source', basic_apps.Join)
   config.app(c, 'sink', basic_apps.Sink)
   config.app(c, 'vhag', vhag, {
      mac_address = "52:54:00:00:00:01",
      fake_mac = "02:aa:aa:aa:aa:aa",
      ipv4_address = "10.0.1.1",
   })
   config.link(c, 'source.out -> vhag.wire')
   config.link(c, 'vhag.service -> sink.in1')
   config.link(c, 'vhag.vm -> sink.in2')

   engine.configure(c)
   transmit_packets(engine.app_table.source.output.out, pkts)
   engine.main({duration = 0.1, noreport = true})
   assert(link.stats(engine.app_table.sink.input.in1).rxpackets == 1)
   assert(link.stats(engine.app_table.sink.input.in2).rxpackets == 1)
end

-- Test VM to Service and Wire.
local function test_ipv4_vm_to_service_and_wire(pkts)
   engine.configure(config.new()) -- Clean up engine.
   local c = config.new()
   config.app(c, 'source', basic_apps.Join)
   config.app(c, 'sink', basic_apps.Sink)
   config.app(c, 'vhag', vhag, {
      mac_address = "52:54:00:00:00:01",
      fake_mac = "02:aa:aa:aa:aa:aa",
      ipv4_address = "10.0.1.1",
   })
   config.link(c, 'source.out -> vhag.vm')
   config.link(c, 'vhag.service -> sink.in1')
   config.link(c, 'vhag.wire -> sink.in2')

   engine.configure(c)
   transmit_packets(engine.app_table.source.output.out, pkts)
   engine.main({duration = 0.1, noreport = true})
   assert(link.stats(engine.app_table.sink.input.in1).rxpackets == 1)
   assert(link.stats(engine.app_table.sink.input.in2).rxpackets == 1)
end

-- Test input Service -> Wire.
local function test_ipv4_service_to_wire (pkts)
   local c = config.new()
   config.app(c, 'source', basic_apps.Join)
   config.app(c, 'sink', basic_apps.Sink)
   config.app(c, 'vhag', vhag, {
      mac_address = "52:54:00:00:00:01",
      fake_mac = "02:aa:aa:aa:aa:aa",
      ipv4_address = "10.0.1.1",
      next_hop_mac = "52:54:00:00:00:02",
   })
   config.link(c, 'source.out -> vhag.service')
   config.link(c, 'vhag.wire -> sink.in1')

   engine.configure(c)
   transmit_packets(engine.app_table.source.output.out, pkts)
   engine.main({duration = 0.1, noreport = true})
   assert(link.stats(engine.app_table.sink.input.in1).rxpackets == 1)
end

-- Test input Service -> VM.
local function test_ipv4_service_to_vm (pkts)
   local c = config.new()
   config.app(c, 'source', basic_apps.Join)
   config.app(c, 'sink', basic_apps.Sink)
   config.app(c, 'vhag', vhag, {
      mac_address = "52:54:00:00:00:01",
      fake_mac = "02:aa:aa:aa:aa:aa",
      ipv4_address = "10.0.1.1",
   })
   config.link(c, 'source.out -> vhag.service')
   config.link(c, 'vhag.vm -> sink.in1')

   engine.configure(c)
   transmit_packets(engine.app_table.source.output.out, pkts)
   engine.main({duration = 0.1, noreport = true})
   assert(link.stats(engine.app_table.sink.input.in1).rxpackets == 1)
end

local function flush ()
   C.sleep(0.5)
   engine.configure(config.new())
end

local function test_ipv4_flow ()
   local pkt1 = lib.hexundump ([[
      02:aa:aa:aa:aa:aa 02:99:99:99:99:99 08 00 45 00
      02 18 00 00 00 00 0f 11 d3 61 0a 0a 0a 01 c1 05
      01 64 30 39 04 00 00 26 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00
   ]], 72)
   local pkt2 = lib.hexundump ([[
      ff ff ff ff ff ff a0 88 b4 2c fa ac 08 06 00 01
      08 00 06 04 00 01 a0 88 b4 2c fa ac c0 a8 00 0a
      00 00 00 00 00 00 0a 00 01 01
   ]], 42)
   test_ipv4_wire_to_vm_and_service({pkt1, pkt2})
   flush()
   test_ipv4_vm_to_service_and_wire({pkt1, pkt2})
   flush()
   test_ipv4_service_to_wire({pkt1})
   flush()
   test_ipv4_service_to_vm({pkt1})
   flush()
end

local function test_ipv4_cache_trigger ()
   local pkt = packet.from_string(lib.hexundump([[
      02:aa:aa:aa:aa:aa 02:99:99:99:99:99 08 00 45 00
      02 18 00 00 00 00 0f 11 d3 61 0a 0a 0a 01 c1 05
      01 64 30 39 04 00 00 26 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00
   ]], 72))
   local ether_dhost = "52:54:00:00:00:01"
   local refresh_packet = ipv4_cache_trigger(pkt, ethernet:pton(ether_dhost))
   local eth_hdr = ethernet:new_from_mem(refresh_packet.data, ethernet_header_size)
   assert(ethernet:ntop(eth_hdr:dst()) == ether_dhost)
end

function selftest ()
   print("vhag: selftest")
   test_ipv4_flow()
   test_ipv4_cache_trigger()
end
