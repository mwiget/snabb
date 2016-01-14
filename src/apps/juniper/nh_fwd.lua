module(...,package.seeall)

local app = require("core.app")
local packet = require("core.packet")
local link = require("core.link")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local ipsum = require("lib.checksum").ipsum
local lwutil = require("apps.lwaftr.lwutil")

local ffi = require("ffi")
local C = ffi.C
local cast = ffi.cast

local n_ether_hdr_size = 14
local n_ipv4_hdr_size = 20
local n_ethertype_ipv4 = C.htons(0x0800)
local n_ethertype_ipv6 = C.htons(0x86DD)
local n_ipencap = 4
local n_cache_src_ipv4 = ipv4:pton("0.0.0.0")
local n_cache_src_ipv6 = ipv6:pton("fe80::")

local receive, transmit = link.receive, link.transmit
local htons = lwutil.htons

--- # `nh_fwd` app: Finds next hop mac by sending packets to VM interface

nh_fwd = {}

function send_cache_trigger(r, p, mac)

-- set a bogus source IP address of 0.0.0.0 or fe80::, so we can recognize it
-- later when it comes back from the vMX.
-- TODO: tried initially to use ::0 as source, but such packets are discarded
-- by the vmx due to RFC 4007, chapter 9, which also considers the source IPv6
-- address.
-- Using the link local address fe80::, the packets are properly routed back
-- thru the same interface. Not sure if its ok to use that address or if there
-- is a better way.

  local eth_hdr = cast(ethernet._header_ptr_type, p.data)
  local ethertype = eth_hdr.ether_type
  local ipv4_hdr = cast(ipv4._header_ptr_type, p.data + n_ether_hdr_size)
  local ipv6_hdr = cast(ipv6._header_ptr_type, p.data + n_ether_hdr_size)

  if ethertype == n_ethertype_ipv4 then
    ipv4_hdr.src_ip = n_cache_src_ipv4
    -- clear checksum before calculation
    ipv4_hdr.checksum =  0  
    ipv4_hdr.checksum = htons(ipsum(p.data + n_ether_hdr_size, n_ipv4_hdr_size, 0))
    transmit(r, p)
  elseif ethertype == n_ethertype_ipv6 then
    ffi.copy(ipv6_hdr.src_ip, n_cache_src_ipv6, 16)
    transmit(r, p)
  else
    packet.free(r)
  end

end

function nh_fwd:new(arg)
  local conf = arg and config.parse_app_arg(arg) or {}
  local mac_address = ethernet:pton(conf.mac_address)
  local ipv6_address = conf.ipv6_address and ipv6:pton(conf.ipv6_address)
  local ipv4_address = conf.ipv4_address and ipv4:pton(conf.ipv4_address)
  local next_hop_mac = conf.next_hop_mac and ethernet:pton(conf.next_hop_mac)
  local service_mac = conf.service_mac and ethernet:pton(conf.service_mac)
  local cache_refresh_interval = conf.cache_refresh_interval or 0
  local description = conf.description or "nh_fwd"
  if next_hop_mac then
    print("next_hop_mac " .. ethernet:ntop(next_hop_mac) .. " on " .. description)
  end
  print(string.format("cache_refresh_interval set to %d seconds",cache_refresh_interval))

  local o = {
    mac_address = mac_address,
    next_hop_mac = next_hop_mac,
    ipv4_address = ipv4_address,
    ipv6_address = ipv6_address,
    description = description,
    service_mac = service_mac,
    cache_refresh_time = tonumber(app.now()),
    cache_refresh_interval = cache_refresh_interval
  }
  return setmetatable(o, {__index=nh_fwd})
end

function nh_fwd:push ()

  local input_lwaftr, output_lwaftr = self.input.lwaftr, self.output.lwaftr
  local input_wire, output_wire = self.input.wire, self.output.wire
  local input_vmx, output_vmx = self.input.vmx, self.output.vmx

  local description = self.description
  local next_hop_mac = self.next_hop_mac
  local service_mac = self.service_mac
  local mac_address = self.mac_address
  local cache_refresh_interval = self.cache_refresh_interval
  local current_time = tonumber(app.now())
  local cache_refresh_time = self.cache_refresh_time

  -- from lwaftr
  for _=1,math.min(link.nreadable(input_lwaftr), link.nwritable(output_wire)) do

    local pkt = receive(input_lwaftr)
    local eth_hdr = cast(ethernet._header_ptr_type, pkt.data)

    if cache_refresh_interval > 0 and output_vmx then
      if current_time > cache_refresh_time + cache_refresh_interval then
        self.cache_refresh_time = current_time
        -- only required for one packet per breathe for packets coming out of lwaftr
        -- because next_hop_mac won't be learned until much later
        cache_refresh_interval = 0
        send_cache_trigger(output_vmx, packet.clone(pkt))
      end
    end

    if next_hop_mac then
      -- set nh mac and send the packet out the wire
      eth_hdr.ether_dhost = next_hop_mac 
      transmit(output_wire, pkt)
    elseif output_vmx then
      -- no nh mac. Punch it to the vMX
      transmit(output_vmx, pkt)
    else
      packet.free(pkt)
    end

  end

  -- from wire
  for _=1,math.min(link.nreadable(input_wire), link.nwritable(output_lwaftr)) do

    local pkt = receive(input_wire)
    local eth_hdr = cast(ethernet._header_ptr_type, pkt.data)
    local ethertype = eth_hdr.ether_type
    local ipv4_hdr = cast(ipv4._header_ptr_type, pkt.data + n_ether_hdr_size)
    local ipv6_hdr = cast(ipv6._header_ptr_type, pkt.data + n_ether_hdr_size)
    local ipv4_address = self.ipv4_address

    --[[
    if ethertype == n_ethertype_ipv4 then
      print(string.format("ipv4 %s", ipv4:ntop(ipv4_hdr.dst_ip)))
    elseif ethertype == n_ethertype_ipv6 then
      print(string.format("ipv6 %s", ipv6:ntop(ipv6_hdr.dst_ip)))
    end
    --]]

    if C.memcmp(eth_hdr.ether_dhost, mac_address, 6) == 0 then
      if ethertype == n_ethertype_ipv4 and ipv4_hdr.dst_ip ~= ipv4_address then
        transmit(output_lwaftr, pkt)
      elseif ethertype == n_ethertype_ipv6 and ipv6_hdr.next_header == n_ipencap then
        transmit(output_lwaftr, pkt)
      elseif output_vmx then
        transmit(output_vmx, pkt)
      else
        packet.free(pkt)
      end
    elseif output_vmx then
      transmit(output_vmx, pkt)
    else
      packet.free(pkt)
    end

  end

  -- from vmx: most packets will go straight out the wire, so check
  -- for room in the outbound wire queue, even though some packets may 
  -- actually go to lwaftr (via service mac)
  --
  local cache_refresh_interval = self.cache_refresh_interval
  if input_vmx then
    for _=1,math.min(link.nreadable(input_vmx), link.nwritable(output_wire)) do

      local pkt = receive(input_vmx)
      local eth_hdr = cast(ethernet._header_ptr_type, pkt.data)
      local ethertype = eth_hdr.ether_type
      local ipv4_hdr = cast(ipv4._header_ptr_type, pkt.data + n_ether_hdr_size)
      local ipv6_hdr = cast(ipv6._header_ptr_type, pkt.data + n_ether_hdr_size)

      if service_mac and C.memcmp(eth_hdr.ether_dhost, service_mac, 6) == 0 then
        transmit(output_lwaftr, pkt)
      elseif cache_refresh_interval > 0 then
        if ethertype == n_ethertype_ipv4 and C.memcmp(ipv4_hdr.src_ip, n_cache_src_ipv4,4) == 0 then    
          -- our magic cache next-hop resolution packet. Never send this out
          self.next_hop_mac = eth_hdr.ether_dhost
--          print(description .. " learning ipv4 nh mac address " .. ethernet:ntop(self.next_hop_mac))
          packet.free(pkt)
        elseif ethertype == n_ethertype_ipv6 and C.memcmp(ipv6_hdr.src_ip, n_cache_src_ipv6,16) == 0 then
          self.next_hop_mac = eth_hdr.ether_dhost
--          print(description .. " learning ipv6 nh mac address " .. ethernet:ntop(self.next_hop_mac))
          packet.free(pkt)
        else
          transmit(output_wire, pkt)
        end
      else
        transmit(output_wire, pkt)
      end

    end
  end

end
