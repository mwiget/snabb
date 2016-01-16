module(...,package.seeall)

local app = require("core.app")
local packet = require("core.packet")
local link = require("core.link")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local udp = require("lib.protocol.udp")
local ipv6 = require("lib.protocol.ipv6")
local ipsum = require("lib.checksum").ipsum
local lwutil = require("apps.lwaftr.lwutil")

local ffi = require("ffi")
local C = ffi.C
local cast = ffi.cast

local rd32, wr32 = lwutil.rd32, lwutil.wr32

local receive, transmit = link.receive, link.transmit

--- # `generator` app: Finds next hop mac by sending packets to VM interface

generator = {}

function generator:new(arg)
  local conf = arg and config.parse_app_arg(arg) or {}
  local mac_address = ethernet:pton(conf.mac)
  local ipv4_address = conf.ip and ipv4:pton(conf.ip)
  local count = conf.count or 1
  local port = conf.port or 1024
  local payload_size = conf.size or 0
  local ipv4_address_offset = 0
  local debug = conf.debug or 0

  print(string.format("debug level %d", debug))

  local master_pkt = packet.allocate()
  local eth_hdr = cast(ethernet._header_ptr_type, master_pkt.data)
  eth_hdr.ether_dhost = mac_address
  eth_hdr.ether_shost = ethernet:pton("46:46:46:46:46:46")
  eth_hdr.ether_type = C.htons(0x0800)

  local ipv4_hdr = cast(ipv4._header_ptr_type, master_pkt.data + 14)
  ipv4_hdr.src_ip = ipv4:pton("1.1.1.1")
  ipv4_hdr.protocol = 17
  ipv4_hdr.ttl = 15
  ipv4_hdr.ihl_v_tos = C.htons(0x4500) -- v4
  ipv4_hdr.id = 0
  ipv4_hdr.frag_off = 0
  ipv4_hdr.total_length = C.htons(28 + payload_size)

  local udp_hdr = cast(udp._header_ptr_type, master_pkt.data + 34)
  udp_hdr.src_port = C.htons(12345)
  udp_hdr.len = C.htons(payload_size)
  udp_hdr.checksum = 0

  local master_pkt_length = 34 + 8 + payload_size

  local o = {
    ipv4_address = ipv4_address,
    ipv4_address_offset = ipv4_address_offset,
    count = count,
    port = port,
    current_count = 0,
    current_port = port,
    master_pkt_length = master_pkt_length,
    master_pkt = master_pkt,
    ipv4_hdr = ipv4_hdr,
    udp_hdr = udp_hdr,
    debug = debug
  }
  return setmetatable(o, {__index=generator})
end

function generator:push ()

  local input = self.input.input
  local output = self.output.output

  -- trash any incoming packets for now
  for _=1,link.nreadable(input) do
    local pkt = receive(input)
    packet.free(pkt)
  end

  local master_pkt = self.master_pkt
  local ipv4_hdr = self.ipv4_hdr
  local udp_hdr = self.udp_hdr
  local debug = self.debug

  local link_writable = link.nwritable(output)
  if debug > 1 then
    link_writable = 1
  end

  for _=1,link_writable do

    ipv4_hdr.dst_ip = self.ipv4_address 
    local ipdst = C.ntohl(rd32(ipv4_hdr.dst_ip))
    ipdst = C.htonl(ipdst + self.ipv4_address_offset)
    wr32(ipv4_hdr.dst_ip, ipdst)
    udp_hdr.dst_port = C.htons(self.current_port)
    ipv4_hdr.checksum =  0
    ipv4_hdr.checksum = C.htons(ipsum(master_pkt.data + 14, 20, 0))

    if debug > 1 then
      print(string.format("sending packet for %s port %d payload %d bytes", ipv4:ntop(ipv4_hdr.dst_ip), C.ntohs(udp_hdr.dst_port), C.ntohs(udp_hdr.len) ))
      C.usleep(10000)
    end


    local pkt = packet.allocate()
    pkt.length = self.master_pkt_length
    ffi.copy(pkt.data, master_pkt.data, pkt.length)

    self.current_count = self.current_count + 1
    self.current_port = self.current_port + self.port

    if self.current_port > 65535 then
      self.current_port = self.port
      self.ipv4_address_offset = self.ipv4_address_offset + 1
    end

    if self.current_count >= self.count then
      self.current_count = 0
      self.current_port = self.port
      self.ipv4_address_offset = 0
    end

    transmit(output, pkt)

  end

end
