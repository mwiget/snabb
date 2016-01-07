module(..., package.seeall)

local constants = require("apps.lwaftr.constants")
local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local ipv6 = require("lib.protocol.ipv6")
local lib = require("core.lib")
local lwutil = require("apps.lwaftr.lwutil")

local cast = ffi.cast
local bitfield = lib.bitfield
local wr16, wr32 = lwutil.wr16, lwutil.wr32
local htons, htonl = lwutil.htons, lwutil.htonl
local ntohs, ntohl = htons, htonl

-- Transitional header handling library.
-- Over the longer term, something more lib.protocol-like has some nice advantages.

-- All addresses should be in network byte order, as should eth_type and vlan_tag.
-- payload lengths should be in host byte order.
-- next_hdr_type and dscp_and_ecn are <= 1 byte, so byte order is irrelevant.

function write_eth_header(dst_ptr, ether_src, ether_dst, eth_type, vlan_tag)
   local eth_hdr = cast(ethernet._header_ptr_type, dst_ptr)
   eth_hdr.ether_shost = ether_src
   eth_hdr.ether_dhost = ether_dst
   if vlan_tag then -- TODO: don't have bare constant offsets here
      wr32(dst_ptr + 12, vlan_tag)
      wr16(dst_ptr + 16, eth_type)
   else
      eth_hdr.ether_type = eth_type
   end
end

function write_ipv6_header(dst_ptr, ipv6_src, ipv6_dst, dscp_and_ecn, next_hdr_type, payload_length)
   local ipv6_hdr = cast(ipv6._header_ptr_type, dst_ptr)
   ffi.fill(ipv6_hdr, ffi.sizeof(ipv6_hdr), 0)
   bitfield(32, ipv6_hdr, 'v_tc_fl', 0, 4, 6)            -- IPv6 Version
   bitfield(32, ipv6_hdr, 'v_tc_fl', 4, 8, dscp_and_ecn) -- Traffic class
   ipv6_hdr.payload_length = htons(payload_length)
   ipv6_hdr.next_header = next_hdr_type
   ipv6_hdr.hop_limit = constants.default_ttl
   ipv6_hdr.src_ip = ipv6_src
   ipv6_hdr.dst_ip = ipv6_dst
end
