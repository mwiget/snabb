module(..., package.seeall)

local bt = require("apps.lwaftr.binding_table")
local constants = require("apps.lwaftr.constants")
local dump = require('apps.lwaftr.dump')
local icmp = require("apps.lwaftr.icmp")
local lwconf = require("apps.lwaftr.conf")
local lwdebug = require("apps.lwaftr.lwdebug")
local lwheader = require("apps.lwaftr.lwheader")
local lwutil = require("apps.lwaftr.lwutil")
local counter = require("core.counter")

local channel = require("apps.lwaftr.channel")
local messages = require("apps.lwaftr.messages")

local checksum = require("lib.checksum")
local ethernet = require("lib.protocol.ethernet")
local ipv6 = require("lib.protocol.ipv6")
local ipv4 = require("lib.protocol.ipv4")
local packet = require("core.packet")
local lib = require("core.lib")
local bit = require("bit")
local ffi = require("ffi")

local band, bor, bnot = bit.band, bit.bor, bit.bnot
local rshift, lshift = bit.rshift, bit.lshift
local cast = ffi.cast
local receive, transmit = link.receive, link.transmit
local rd16, wr16, rd32, ipv6_equals = lwutil.rd16, lwutil.wr16, lwutil.rd32, lwutil.ipv6_equals
local is_ipv4, is_ipv6 = lwutil.is_ipv4, lwutil.is_ipv6
local get_ihl_from_offset = lwutil.get_ihl_from_offset
local htons, htonl = lwutil.htons, lwutil.htonl
local ntohs, ntohl = htons, htonl
local keys = lwutil.keys
local write_eth_header, write_ipv6_header = lwheader.write_eth_header, lwheader.write_ipv6_header

local debug = false

-- Local bindings for constants that are used in the hot path of the
-- data plane.  Not having them here is a 1-2% performance penalty.
local ethernet_header_size = constants.ethernet_header_size
local n_ethertype_ipv4 = constants.n_ethertype_ipv4
local n_ethertype_ipv6 = constants.n_ethertype_ipv6

local function get_ethernet_payload(pkt)
   return pkt.data + ethernet_header_size
end
local function get_ethernet_payload_length(pkt)
   return pkt.length - ethernet_header_size
end

local o_ipv4_checksum = constants.o_ipv4_checksum
local o_ipv4_dscp_and_ecn = constants.o_ipv4_dscp_and_ecn
local o_ipv4_dst_addr = constants.o_ipv4_dst_addr
local o_ipv4_flags = constants.o_ipv4_flags
local o_ipv4_identification = constants.o_ipv4_identification
local o_ipv4_proto = constants.o_ipv4_proto
local o_ipv4_src_addr = constants.o_ipv4_src_addr
local o_ipv4_total_length = constants.o_ipv4_total_length
local o_ipv4_ttl = constants.o_ipv4_ttl
local o_ipv4_ver_and_ihl = constants.o_ipv4_ver_and_ihl

local function get_ipv4_header_length(ptr)
   local ver_and_ihl = ptr[0]
   return lshift(band(ver_and_ihl, 0xf), 2)
end
local function get_ipv4_total_length(ptr)
   return ntohs(rd16(ptr + o_ipv4_total_length))
end
local function get_ipv4_src_address_ptr(ptr)
   return ptr + o_ipv4_src_addr
end
local function get_ipv4_dst_address_ptr(ptr)
   return ptr + o_ipv4_dst_addr
end
local function get_ipv4_src_address(ptr)
   return ntohl(rd32(get_ipv4_src_address_ptr(ptr)))
end
local function get_ipv4_dst_address(ptr)
   return ntohl(rd32(get_ipv4_dst_address_ptr(ptr)))
end
local function get_ipv4_proto(ptr)
   return ptr[o_ipv4_proto]
end
local function get_ipv4_flags(ptr)
   return ptr[o_ipv4_flags]
end
local function get_ipv4_dscp_and_ecn(ptr)
   return ptr[o_ipv4_dscp_and_ecn]
end
local function get_ipv4_payload(ptr)
   return ptr + get_ipv4_header_length(ptr)
end
local function get_ipv4_payload_src_port(ptr)
   -- Assumes that the packet is TCP or UDP.
   return ntohs(rd16(get_ipv4_payload(ptr)))
end
local function get_ipv4_payload_dst_port(ptr)
   -- Assumes that the packet is TCP or UDP.
   return ntohs(rd16(get_ipv4_payload(ptr) + 2))
end

local ipv6_fixed_header_size = constants.ipv6_fixed_header_size
local o_ipv6_dst_addr = constants.o_ipv6_dst_addr
local o_ipv6_next_header = constants.o_ipv6_next_header
local o_ipv6_src_addr = constants.o_ipv6_src_addr

local function get_ipv6_src_address(ptr)
   return ptr + o_ipv6_src_addr
end
local function get_ipv6_dst_address(ptr)
   return ptr + o_ipv6_dst_addr
end
local function get_ipv6_next_header(ptr)
   return ptr[o_ipv6_next_header]
end
local function get_ipv6_payload(ptr)
   -- FIXME: Deal with multiple IPv6 headers?
   return ptr + ipv6_fixed_header_size
end

local proto_icmp = constants.proto_icmp
local proto_icmpv6 = constants.proto_icmpv6
local proto_ipv4 = constants.proto_ipv4

local function get_icmp_type(ptr)
   return ptr[0]
end
local function get_icmp_code(ptr)
   return ptr[1]
end
local function get_icmpv4_echo_identifier(ptr)
   return ntohs(rd16(ptr + constants.o_icmpv4_echo_identifier))
end
local function get_icmp_mtu(ptr)
   local next_hop_mtu_offset = 6
   return ntohs(rd16(ptr + next_hop_mtu_offset))
end
local function get_icmp_payload(ptr)
   return ptr + constants.icmp_base_size
end

local function drop(pkt)
   packet.free(pkt)
end

local transmit_icmpv6_with_rate_limit

local function init_transmit_icmpv6_with_rate_limit(lwstate)
   assert(lwstate.icmpv6_rate_limiter_n_seconds > 0,
      "Incorrect icmpv6_rate_limiter_n_seconds value, must be > 0")
   assert(lwstate.icmpv6_rate_limiter_n_packets >= 0,
      "Incorrect icmpv6_rate_limiter_n_packets value, must be >= 0")
   local icmpv6_rate_limiter_n_seconds = lwstate.icmpv6_rate_limiter_n_seconds
   local icmpv6_rate_limiter_n_packets = lwstate.icmpv6_rate_limiter_n_packets
   local counter = 0
   local last_time
   return function (o, pkt)
      local cur_now = tonumber(engine.now())
      last_time = last_time or cur_now
      -- Reset if elapsed time reached.
      if cur_now - last_time >= icmpv6_rate_limiter_n_seconds then
         last_time = cur_now
         counter = 0
      end
      -- Send packet if limit not reached.
      if counter < icmpv6_rate_limiter_n_packets then
         counter = counter + 1
         return transmit(o, pkt)
      else
         return drop(pkt)
      end
   end
end

LwAftr = {}

-- Counters for statistics.
v4sentPacket    = counter.open("lwaftr_v4/sentPacket")
v4sentByte      = counter.open("lwaftr_v4/sentByte")
v4rcvdPacket    = counter.open("lwaftr_v4/rcvdPacket")
v4rcvdByte      = counter.open("lwaftr_v4/rcvdByte")
v4droppedPacket = counter.open("lwaftr_v4/droppedPacket")
v4droppedByte   = counter.open("lwaftr_v4/droppedByte")

v6sentPacket    = counter.open("lwaftr_v6/sentPacket")
v6sentByte      = counter.open("lwaftr_v6/sentByte")
v6rcvdPacket    = counter.open("lwaftr_v6/rcvdPacket")
v6rcvdByte      = counter.open("lwaftr_v6/rcvdByte")
v6droppedPacket = counter.open("lwaftr_v6/droppedPacket")
v6droppedByte   = counter.open("lwaftr_v6/droppedByte")

function LwAftr:new(conf)
   if type(conf) == 'string' then
      conf = lwconf.load_lwaftr_config(conf)
   end
   if conf.debug then debug = true end
   local o = setmetatable({}, {__index=LwAftr})
   o.conf = conf

   -- FIXME: Access these from the conf instead of splatting them onto
   -- the lwaftr app, if there is no performance impact.
   o.aftr_ipv4_ip = conf.aftr_ipv4_ip
   o.aftr_ipv6_ip = conf.aftr_ipv6_ip
   o.aftr_mac_b4_side = conf.aftr_mac_b4_side
   o.aftr_mac_inet_side = conf.aftr_mac_inet_side
   o.next_hop6_mac = conf.next_hop6_mac or ethernet:pton("00:00:00:00:00:00")
   o.hairpinning = conf.hairpinning
   o.icmpv6_rate_limiter_n_packets = conf.icmpv6_rate_limiter_n_packets
   o.icmpv6_rate_limiter_n_seconds = conf.icmpv6_rate_limiter_n_seconds
   o.inet_mac = conf.inet_mac
   o.ipv4_mtu = conf.ipv4_mtu
   o.ipv6_mtu = conf.ipv6_mtu
   o.policy_icmpv4_incoming = conf.policy_icmpv4_incoming
   o.policy_icmpv4_outgoing = conf.policy_icmpv4_outgoing
   o.policy_icmpv6_incoming = conf.policy_icmpv6_incoming
   o.policy_icmpv6_outgoing = conf.policy_icmpv6_outgoing

   o.binding_table = conf.preloaded_binding_table or bt.load(o.conf.binding_table)

   o.control = channel.create('lwaftr/control', messages.lwaftr_message_t)

   transmit_icmpv6_with_rate_limit = init_transmit_icmpv6_with_rate_limit(o)
   if debug then lwdebug.pp(conf) end
   return o
end

local function decrement_ttl(pkt)
   local ipv4_header = get_ethernet_payload(pkt)
   local checksum = bnot(ntohs(rd16(ipv4_header + o_ipv4_checksum)))
   local old_ttl = ipv4_header[o_ipv4_ttl]
   if old_ttl == 0 then return 0 end
   local new_ttl = band(old_ttl - 1, 0xff)
   ipv4_header[o_ipv4_ttl] = new_ttl
   -- Now fix up the checksum.  o_ipv4_ttl is the first byte in the
   -- 16-bit big-endian word, so the difference to the overall sum is
   -- multiplied by 0xff.
   checksum = checksum + lshift(new_ttl - old_ttl, 8)
   -- Now do the one's complement 16-bit addition of the 16-bit words of
   -- the checksum, which necessarily is a 32-bit value.  Two carry
   -- iterations will suffice.
   checksum = band(checksum, 0xffff) + rshift(checksum, 16)
   checksum = band(checksum, 0xffff) + rshift(checksum, 16)
   wr16(ipv4_header + o_ipv4_checksum, htons(bnot(checksum)))
   return new_ttl
end

-- https://www.ietf.org/id/draft-farrer-softwire-br-multiendpoints-01.txt
-- Return the IPv6 address of the B4 and the AFTR.
local function binding_lookup_ipv4(lwstate, ipv4_ip, port)
   if debug then
      print(lwdebug.format_ipv4(ipv4_ip), 'port: ', port, string.format("%x", port))
      lwdebug.pp(lwstate.binding_table)
   end
   local val = lwstate.binding_table:lookup(ipv4_ip, port)
   if val then
      return val.b4_ipv6, lwstate.binding_table:get_br_address(val.br)
   end
   if debug then
      print("Nothing found for ipv4:port", lwdebug.format_ipv4(ipv4_ip),
      string.format("%i (0x%x)", port, port))
   end
end

local function ipv4_in_binding_table(lwstate, ip)
   return lwstate.binding_table:is_managed_ipv4_address(ip)
end

local function in_binding_table(lwstate, ipv6_src_ip, ipv6_dst_ip, ipv4_src_ip, ipv4_src_port)
   local b4, br = binding_lookup_ipv4(lwstate, ipv4_src_ip, ipv4_src_port)
   return b4 and ipv6_equals(b4, ipv6_src_ip) and ipv6_equals(br, ipv6_dst_ip)
end

local function transmit_ipv4(lwstate, pkt)
   local ipv4_header = get_ethernet_payload(pkt)
   local dst_ip = get_ipv4_dst_address(ipv4_header)
   if lwstate.hairpinning and ipv4_in_binding_table(lwstate, dst_ip) then
      -- The destination address is managed by the lwAFTR, so we need to
      -- hairpin this packet.  Enqueue on the IPv4 interface, as if it
      -- came from the internet.
      return transmit(lwstate.input.v4, pkt)
   else
      return transmit(lwstate.o4, pkt)
   end
end

local function transmit_ipv4_reply(lwstate, pkt, orig_pkt)
   counter.add(v4droppedPacket)
   counter.add(v4droppedByte, pkt.length)
   drop(orig_pkt)
   return transmit_ipv4(lwstate, pkt)
end

-- ICMPv4 type 3 code 1, as per RFC 7596.
-- The target IPv4 address + port is not in the table.
local function drop_ipv4_packet_to_unreachable_host(lwstate, pkt, to_ip)
   if lwstate.policy_icmpv4_outgoing == lwconf.policies['DROP then
      -- ICMP error messages off by policy; silently drop.
      return drop(pkt)
   end

   if get_ipv4_proto(get_ethernet_payload(pkt)) == proto_icmp then
      -- RFC 7596 section 8.1 requires us to silently drop incoming
      -- ICMPv4 messages that don't match the binding table.
      return drop(pkt)
   end

   local ipv4_header = get_ethernet_payload(pkt)
   local to_ip = get_ipv4_src_address_ptr(ipv4_header)
   local icmp_config = {
      type = constants.icmpv4_dst_unreachable,
      code = constants.icmpv4_host_unreachable,
   }
   local icmp_dis = icmp.new_icmpv4_packet(
      lwstate.aftr_mac_inet_side, lwstate.inet_mac, lwstate.aftr_ipv4_ip,
      to_ip, pkt, ethernet_header_size, icmp_config)
   return transmit_ipv4_reply(lwstate, icmp_dis, pkt)
end

-- ICMPv6 type 1 code 5, as per RFC 7596.
-- The source (ipv6, ipv4, port) tuple is not in the table.
local function drop_ipv6_packet_from_bad_softwire(lwstate, pkt)
   if lwstate.policy_icmpv6_outgoing == lwconf.policies['DROP'] then
      -- ICMP error messages off by policy; silently drop.
      counter.add(v6droppedPacket)
      counter.add(v6droppedByte, pkt.length)
      return drop(pkt)
   end

   local ipv6_header = get_ethernet_payload(pkt)
   local ipv6_src_addr = get_ipv6_src_address(ipv6_header)
   local icmp_config = {type = constants.icmpv6_dst_unreachable,
                        code = constants.icmpv6_failed_ingress_egress_policy,
                       }
   local b4fail_icmp = icmp.new_icmpv6_packet(
      lwstate.aftr_mac_b4_side, lwstate.next_hop6_mac, lwstate.aftr_ipv6_ip,
      ipv6_src_addr, pkt, ethernet_header_size, icmp_config)
   counter.add(v6droppedPacket)
   counter.add(v6droppedByte, pkt.length)
   drop(pkt)
   transmit_icmpv6_with_rate_limit(lwstate.o6, b4fail_icmp)
end

local function encapsulating_packet_with_df_flag_would_exceed_mtu(lwstate, pkt)
   local payload_length = get_ethernet_payload_length(pkt)
   if payload_length + ipv6_fixed_header_size <= lwstate.ipv6_mtu then
      -- Packet will not exceed MTU.
      return false
   end
   -- The result would exceed the IPv6 MTU; signal an error via ICMPv4 if
   -- the IPv4 fragment has the DF flag.
   return band(get_ipv4_flags(get_ethernet_payload(pkt)), 0x40) == 0x40
end

local function cannot_fragment_df_packet_error(lwstate, pkt)
   -- According to RFC 791, the original packet must be discarded.
   -- Return a packet with ICMP(3, 4) and the appropriate MTU
   -- as per https://tools.ietf.org/html/rfc2473#section-7.2
   if debug then lwdebug.print_pkt(pkt) end
   -- The ICMP packet should be set back to the packet's source.
   local dst_ip = get_ipv4_src_address_ptr(get_ethernet_payload(pkt))
   local icmp_config = {
      type = constants.icmpv4_dst_unreachable,
      code = constants.icmpv4_datagram_too_big_df,
      extra_payload_offset = 0,
      next_hop_mtu = lwstate.ipv6_mtu - constants.ipv6_fixed_header_size,
   }
   return icmp.new_icmpv4_packet(lwstate.aftr_mac_inet_side, lwstate.inet_mac,
                                 lwstate.aftr_ipv4_ip, dst_ip, pkt,
                                 ethernet_header_size, icmp_config)
end

local function encapsulate_and_transmit(lwstate, pkt, ipv6_dst, ipv6_src)
   -- Do not encapsulate packets that now have a ttl of zero or wrapped around
   local ttl = decrement_ttl(pkt)
   if ttl == 0 then
      if lwstate.policy_icmpv4_outgoing == lwconf.policies['DENY'] then
         return drop(pkt)
      end
      local ipv4_header = get_ethernet_payload(pkt)
      local dst_ip = get_ipv4_src_address_ptr(ipv4_header)
      local icmp_config = {type = constants.icmpv4_time_exceeded,
                           code = constants.icmpv4_ttl_exceeded_in_transit,
                           }
      local reply = icmp.new_icmpv4_packet(
         lwstate.aftr_mac_inet_side, lwstate.inet_mac, lwstate.aftr_ipv4_ip,
         dst_ip, pkt, ethernet_header_size, icmp_config)
      return transmit_ipv4_reply(lwstate, reply, pkt)
   end

   if debug then print("ipv6", ipv6_src, ipv6_dst) end

   local next_hdr_type = proto_ipv4
   local ether_src = lwstate.aftr_mac_b4_side
   local ether_dst = lwstate.next_hop6_mac

   if encapsulating_packet_with_df_flag_would_exceed_mtu(lwstate, pkt) then
      local reply = cannot_fragment_df_packet_error(lwstate, pkt)
      return transmit_ipv4_reply(lwstate, reply, pkt)
   end

   local payload_length = get_ethernet_payload_length(pkt)
   local l3_header = get_ethernet_payload(pkt)
   local dscp_and_ecn = get_ipv4_dscp_and_ecn(l3_header)
   packet.shiftright(pkt, ipv6_fixed_header_size)
   write_eth_header(pkt.data, ether_src, ether_dst, n_ethertype_ipv6)
   write_ipv6_header(l3_header, ipv6_src, ipv6_dst,
                     dscp_and_ecn, next_hdr_type, payload_length)

   if debug then
      print("encapsulated packet:")
      lwdebug.print_pkt(pkt)
   end
   counter.add(v6sentPacket)
   counter.add(v6sentByte, pkt.length)

   return transmit(lwstate.o6, pkt)
end

local function enqueue_lookup(lwstate, pkt, ipv4, port, flush)
   local bt = lwstate.binding_table
   if bt:enqueue_lookup(pkt, ipv4, port) then
      flush(lwstate)
   end
end

local function flush_encapsulation(lwstate)
   local bt = lwstate.binding_table
   bt:process_lookup_queue()
   for n = 0, bt.lookup_queue_len - 1 do
      local pkt, ipv6_dst, ipv6_src = bt:get_enqueued_lookup(n)
      if ipv6_dst then
         encapsulate_and_transmit(lwstate, pkt, ipv6_dst, ipv6_src)
      else
         -- Lookup failed.
         if debug then print("lookup failed") end
         counter.add(v4droppedPacket)
         counter.add(v4droppedByte, pkt.length)
         drop_ipv4_packet_to_unreachable_host(lwstate, pkt)
      end
   end
   bt:reset_lookup_queue()
end

local function enqueue_encapsulation(lwstate, pkt, ipv4, port)
   enqueue_lookup(lwstate, pkt, ipv4, port, flush_encapsulation)
end

local function icmpv4_incoming(lwstate, pkt)
   local ipv4_header = get_ethernet_payload(pkt)
   local ipv4_header_size = get_ipv4_header_length(ipv4_header)
   local icmp_header = get_ipv4_payload(ipv4_header)
   local icmp_type = get_icmp_type(icmp_header)

   -- RFC 7596 is silent on whether to validate echo request/reply checksums.
   -- ICMP checksums SHOULD be validated according to RFC 5508.
   -- Choose to verify the echo reply/request ones too.
   -- Note: the lwaftr SHOULD NOT validate the transport checksum of the embedded packet.
   -- Were it to nonetheless do so, RFC 4884 extension headers MUST NOT
   -- be taken into account when validating the checksum
   local icmp_bytes = get_ipv4_total_length(ipv4_header) - ipv4_header_size
   if checksum.ipsum(icmp_header, icmp_bytes, 0) ~= 0 then
      -- Silently drop the packet, as per RFC 5508
      return drop(pkt)
   end

   local ipv4_dst = get_ipv4_dst_address(ipv4_header)
   local port

   -- checksum was ok
   if icmp_type == constants.icmpv4_echo_request then
      -- For an incoming ping from the IPv4 internet, assume port == 0
      -- for the purposes of looking up a softwire in the binding table.
      -- This will allow ping to a B4 on an IPv4 without port sharing.
      -- It also has the nice property of causing a drop if the IPv4 has
      -- any reserved ports.
      --
      -- RFC 7596 section 8.1 seems to suggest that we should use the
      -- echo identifier for this purpose, but that only makes sense for
      -- echo requests originating from a B4, to identify the softwire
      -- of the source.  It can't identify a destination softwire.  This
      -- makes sense because you can't really "ping" a port-restricted
      -- IPv4 address.
      port = 0
   elseif icmp_type == constants.icmpv4_echo_reply then
      -- A reply to a ping that originally issued from a subscriber on
      -- the B4 side; the B4 set the port in the echo identifier, as per
      -- RFC 7596, section 8.1, so use that to look up the destination
      -- softwire.
      port = get_icmpv4_echo_identifier(icmp_header)
   else
      -- As per REQ-3, use the ip address embedded in the ICMP payload,
      -- assuming that the payload is shaped like TCP or UDP with the
      -- ports first.
      local embedded_ipv4_header = get_icmp_payload(icmp_header)
      port = get_ipv4_payload_src_port(embedded_ipv4_header)
   end

   return enqueue_encapsulation(lwstate, pkt, ipv4_dst, port)
end

-- The incoming packet is a complete one with ethernet headers.
-- FIXME: Verify that the total_length declared in the packet is correct.
local function from_inet(lwstate, pkt)
   -- Check incoming ICMP -first-, because it has different binding table lookup logic
   -- than other protocols.
   local ipv4_header = get_ethernet_payload(pkt)
   counter.add(v4rcvdPacket)
   counter.add(v4rcvdByte, pkt.length)
   if get_ipv4_proto(ipv4_header) == proto_icmp then
      if lwstate.policy_icmpv4_incoming == lwconf.policies['DENY'] then
         counter.add(v4droppedPacket)
         counter.add(v4droppedByte, pkt.length)
         return drop(pkt)
      else
         return icmpv4_incoming(lwstate, pkt)
      end
   end

   -- It's not incoming ICMP.  Assume we can find ports in the IPv4
   -- payload, as in TCP and UDP.  We could check strictly for TCP/UDP,
   -- but that would filter out similarly-shaped protocols like SCTP, so
   -- we optimistically assume that the incoming traffic has the right
   -- shape.
   local dst_ip = get_ipv4_dst_address(ipv4_header)
   local dst_port = get_ipv4_payload_dst_port(ipv4_header)

   return enqueue_encapsulation(lwstate, pkt, dst_ip, dst_port)
end

local function tunnel_unreachable(lwstate, pkt, code, next_hop_mtu)
   local ipv6_header = get_ethernet_payload(pkt)
   local icmp_header = get_ipv6_payload(ipv6_header)
   local embedded_ipv6_header = get_icmp_payload(icmp_header)
   local embedded_ipv4_header = get_ipv6_payload(embedded_ipv6_header)

   local icmp_config = {type = constants.icmpv4_dst_unreachable,
                        code = code,
                        extra_payload_offset = embedded_ipv4_header - ipv6_header,
                        next_hop_mtu = next_hop_mtu
                        }
   local dst_ip = get_ipv4_src_address_ptr(embedded_ipv4_header)
   local icmp_reply = icmp.new_icmpv4_packet(lwstate.aftr_mac_inet_side, lwstate.inet_mac,
                                             lwstate.aftr_ipv4_ip, dst_ip, pkt,
                                             ethernet_header_size, icmp_config)
   return icmp_reply
end

-- FIXME: Verify that the softwire is in the the binding table.
local function icmpv6_incoming(lwstate, pkt)
   local ipv6_header = get_ethernet_payload(pkt)
   local icmp_header = get_ipv6_payload(ipv6_header)
   local icmp_type = get_icmp_type(icmp_header)
   local icmp_code = get_icmp_code(icmp_header)
   if icmp_type == constants.icmpv6_packet_too_big then
      if icmp_code ~= constants.icmpv6_code_packet_too_big then
         -- Invalid code.
         counter.add(v6droppedPacket)
         counter.add(v6droppedByte, pkt.length)
         return drop(pkt)
      end
      local mtu = get_icmp_mtu(icmp_header) - constants.ipv6_fixed_header_size
      local reply = tunnel_unreachable(lwstate, pkt,
                                       constants.icmpv4_datagram_too_big_df,
                                       mtu)
      return transmit_ipv4_reply(lwstate, reply, pkt)
   -- Take advantage of having already checked for 'packet too big' (2), and
   -- unreachable node/hop limit exceeded/paramater problem being 1, 3, 4 respectively
   elseif icmp_type <= constants.icmpv6_parameter_problem then
      -- If the time limit was exceeded, require it was a hop limit code
      if icmp_type == constants.icmpv6_time_limit_exceeded then
         if icmp_code ~= constants.icmpv6_hop_limit_exceeded then
            counter.add(v6droppedPacket)
            counter.add(v6droppedByte, pkt.length)
            return drop(pkt)
         end
      end
      -- Accept all unreachable or parameter problem codes
      local reply = tunnel_unreachable(lwstate, pkt,
                                       constants.icmpv4_host_unreachable)
      return transmit_ipv4_reply(lwstate, reply, pkt)
   else
      -- No other types of ICMPv6, including echo request/reply, are
      -- handled.
      counter.add(v6droppedPacket)
      counter.add(v6droppedByte, pkt.length)
      return drop(pkt)
   end
end

local function flush_decapsulation(lwstate)
   local bt = lwstate.binding_table
   bt:process_lookup_queue()
   for n = 0, bt.lookup_queue_len - 1 do
      local pkt, b4_addr, br_addr = bt:get_enqueued_lookup(n)

      local ipv6_header = get_ethernet_payload(pkt)
      if (b4_addr
          and ipv6_equals(get_ipv6_src_address(ipv6_header), b4_addr)
          and ipv6_equals(get_ipv6_dst_address(ipv6_header), br_addr)) then
         -- Source softwire is valid; decapsulate and forward.
         packet.shiftleft(pkt, ipv6_fixed_header_size)
         write_eth_header(pkt.data, lwstate.aftr_mac_inet_side, lwstate.inet_mac,
                          n_ethertype_ipv4)
         counter.add(v4sentPacket)
         counter.add(v4sentByte, pkt.length)
         transmit_ipv4(lwstate, pkt)
      else
         drop_ipv6_packet_from_bad_softwire(lwstate, pkt)
      end
   end
   bt:reset_lookup_queue()
end

local function enqueue_decapsulation(lwstate, pkt, ipv4, port)
   enqueue_lookup(lwstate, pkt, ipv4, port, flush_decapsulation)
end

-- FIXME: Verify that the packet length is big enough?
local function from_b4(lwstate, pkt)
   local ipv6_header = get_ethernet_payload(pkt)
   local proto = get_ipv6_next_header(ipv6_header)

   counter.add(v6rcvdPacket)
   counter.add(v6rcvdByte, pkt.length)

   if proto ~= proto_ipv4 then 
      if proto == proto_icmpv6 then
         if lwstate.policy_icmpv6_incoming == lwconf.policies['DENY'] then
            counter.add(v6droppedPacket)
            counter.add(v6droppedByte, pkt.length)
            return drop(pkt)
         else
            return icmpv6_incoming(lwstate, pkt)
         end
      else
         -- Drop packet with unknown protocol.
         counter.add(v6droppedPacket)
         counter.add(v6droppedByte, pkt.length)
         return drop(pkt)
      end
   end

   local tunneled_ipv4_header = get_ipv6_payload(ipv6_header)
   local port
   if get_ipv4_proto(tunneled_ipv4_header) == proto_icmp then
      local icmp_header = get_ipv4_payload(tunneled_ipv4_header)
      local icmp_type = get_icmp_type(icmp_header)
      if icmp_type == constants.icmpv4_echo_request then
         -- A ping going out from the B4 to the internet; the B4 will
         -- encode a port in its range into the echo identifier, as per
         -- RFC 7596 section 8.
         port = get_icmpv4_echo_identifier(icmp_header)
      elseif icmp_type == constants.icmpv4_echo_reply then
         -- A reply to a ping, coming from the B4.  Only B4s whose
         -- softwire is associated with port 0 are pingable.  See
         -- icmpv4_incoming for more discussion.
         port = 0
      else
         -- Otherwise it's an error in response to a non-ICMP packet,
         -- routed to the B4 via the ports in IPv4 payload.  Extract
         -- these ports from the embedded packet fragment in the ICMP
         -- payload.
         local embedded_ipv4_header = get_icmp_payload(icmp_header)
         port = get_ipv4_payload_src_port(embedded_ipv4_header)
      end
   else
      -- It's not ICMP.  Assume we can find ports in the IPv4 payload,
      -- as in TCP and UDP.  We could check strictly for TCP/UDP, but
      -- that would filter out similarly-shaped protocols like SCTP, so
      -- we optimistically assume that the incoming traffic has the
      -- right shape.
      port = get_ipv4_payload_src_port(tunneled_ipv4_header)
   end

   local ipv4 = get_ipv4_src_address(tunneled_ipv4_header)
   return enqueue_decapsulation(lwstate, pkt, ipv4, port)
end

function LwAftr:push ()
   local i4, i6 = self.input.v4, self.input.v6
   local o4, o6 = self.output.v4, self.output.v6
   self.o4, self.o6 = o4, o6

   do
      local msg = self.control:pop()
      if msg then
         if msg.kind == messages.lwaftr_message_reload then
            print('Reloading binding table.')
            self.binding_table = bt.load(self.conf.binding_table)
            -- We don't know why yet, but something about reloading a
            -- binding table makes LuaJIT switch to side traces instead
            -- of main traces.  Very weird.  Flushing the JIT state
            -- fixes it, but it's quite a big hammer!
            require('jit').flush()
         elseif msg.kind == messages.lwaftr_message_dump_config then
            dump.dump_configuration(self)
            dump.dump_binding_table(self)
         else
            print('Unhandled message: '..tostring(msg))
         end
      end
   end

   for _=1,link.nreadable(i6) do
      -- Decapsulate incoming IPv6 packets from the B4 interface and
      -- push them out the V4 link, unless they need hairpinning, in
      -- which case enqueue them on the incoming V4 link.  Drop anything
      -- that's not IPv6.
      local pkt = receive(i6)
      if is_ipv6(pkt) then
         from_b4(self, pkt)
      else
         counter.add(v6droppedPacket)
         counter.add(v6droppedByte, pkt.length)
         drop(pkt)
      end
   end
   flush_decapsulation(self)

   for _=1,link.nreadable(i4) do
      -- Encapsulate incoming IPv4 packets, including hairpinned
      -- packets.  Drop anything that's not IPv4.
      local pkt = receive(i4)
      if is_ipv4(pkt) then
         from_inet(self, pkt)
      else
         counter.add(v4droppedPacket)
         counter.add(v4droppedByte, pkt.length)
         drop(pkt)
      end
   end
   flush_encapsulation(self)
end
