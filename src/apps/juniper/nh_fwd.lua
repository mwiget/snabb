module(...,package.seeall)

local app = require("core.app")
local freelist = require("core.freelist")
local packet = require("core.packet")
local link = require("core.link")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")

local ffi = require("ffi")
local C = ffi.C
local cast = ffi.cast

local uint16_ptr_t = ffi.typeof("uint16_t*")

function wr16(offset, val)
  cast(uint16_ptr_t, offset)[0] = val
end

--- # `nh_fwd` app: Finds next hop mac by sending packets to VM interface

nh_fwd = {}

local function hex_dump(cdata,len)
  local buf = ffi.string(cdata,len)
  for i=1,math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then io.write(string.format('%08X  ', i-1)) end
    io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
    if i %  8 == 0 then io.write(' ') end
    if i % 16 == 0 then io.write( buf:sub(i-16+1, i):gsub('%c','.'), '\n' ) end
  end
end

function send_cache_trigger(r, p, mac)

-- set a bogus source IP address of 0.0.0.0 or fe80::, so we can recognize it
-- later when it comes back from the vMX.
-- TODO: tried initially to use ::0 as source, but such packets are discarded
-- by the vmx due to RFC 4007, chapter 9, which also considers the source IPv6
-- address.
-- Using the link local address fe80::, the packets are properly routed back
-- thru the same interface. Not sure if its ok to use that address or if there
-- is a better way.

  local ETH_HDR_SIZE = 14
  local IPV4_HDR_SIZE  = 20
  local IPV6_HDR_SIZE  = 40

  local eth_header = ethernet:new_from_mem(p.data, ETH_HDR_SIZE)
  local ether_type = eth_header:type()
  if 0x0800 == ether_type and p.length > ETH_HDR_SIZE + IPV4_HDR_SIZE then
    -- IPv4 packet
    local ipv4_header = ipv4:new_from_mem(p.data + ETH_HDR_SIZE, IPV4_HDR_SIZE) 
    ipv4_header:src(ipv4:pton('0.0.0.0'))
    wr16(p.data + 24, 0)  -- clear checksum before calculation
    ipv4_header:checksum()
  elseif 0x86dd == ether_type and p.length > ETH_HDR_SIZE + IPV6_HDR_SIZE then
    -- IPv6 packet
    local ipv6_header = ipv6:new_from_mem(p.data + ETH_HDR_SIZE, IPV6_HDR_SIZE) 
    ipv6_header:src(ipv6:pton('fe80::'))
  else
    -- dont know what to do. Drop it silently
    r = nil 
  end
  eth_header:dst(mac)
  if r and not link.full(r) then
    link.transmit(r, p)
  else
    packet.free(p)
  end

end

function nh_fwd:new(arg)
  local conf = arg and config.parse_app_arg(arg) or {}
  local mac_address = ethernet:pton(conf.mac_address)
  local ipv6_address = conf.ipv6_address and ipv6:pton(conf.ipv6_address)
  local ipv4_address = conf.ipv4_address and ipv4:pton(conf.ipv4_address)
  local next_hop_mac = conf.next_hop_mac and ethernet:pton(conf.next_hop_mac)
  local service_mac = conf.service_mac and ethernet:pton(conf.service_mac)
  -- default cache refresh interval set to 30 seconds
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
  -- We expect up to 3 bi-directional queues:
  -- wire: physical interface, either IPv4 or IPv6
  -- lwaftr:  actual service function app (jlwaftr)
  -- vmx:   virtio_user interface of the VM for nh resolution and non-lw4o6 packets 
  -- keep processing packets as long as at least one of the output queues has
  -- capacity (even though that might be the wrong one). This way we won't starve
  -- out an open communication path.

  local ETH_HDR_SIZE = 14
  local IPV4_HDR_SIZE  = 20
  local IPV6_HDR_SIZE  = 40

  -- packets from wire
  local input = self.input.wire
  if input then
    for n = 1,link.nreadable(input) do
      local p = link.receive(input)
      local eth_header = ethernet:new_from_mem(p.data, ETH_HDR_SIZE)
      local output = nil
      local ether_type = eth_header:type()
      local dstmac = eth_header:dst()
      if eth_header:is_mcast(dstmac) then
        output = self.output.vmx
      --  print(string.format("%s: broadcast packet to vmx", self.description))
      elseif eth_header:dst_eq(self.mac_address) then
        output = self.output.vmx
        if 0x0800 == ether_type and p.length > ETH_HDR_SIZE + IPV4_HDR_SIZE then
          -- IPv4 packet from wire
          local ipv4_header = ipv4:new_from_mem(p.data + ETH_HDR_SIZE, IPV4_HDR_SIZE) 
          if self.ipv4_address and ipv4_header:dst_eq(self.ipv4_address) then
            -- local IPv4 destination to vMX, else to lwaftr
            output = self.output.vmx
          else
            output = self.output.lwaftr
          end
        elseif 0x86dd == ether_type and p.length > ETH_HDR_SIZE + IPV6_HDR_SIZE and self.ipv6_address then
          -- IPv6 packet from wire
          local ipv6_header = ipv6:new_from_mem(p.data + ETH_HDR_SIZE, IPV6_HDR_SIZE) 
          if 0x04 == ipv6_header:next_header() then
            output = self.output.lwaftr
          end
        end
      else
      end

      if output and not link.full(output) then
        link.transmit(output, p)
      else
        packet.free(p)
      end
    end
  end

  -- packets from lwaftr
  local input = self.input.lwaftr
  for n = 1,link.nreadable(input) do
    local p = link.receive(input)
    local eth_header = ethernet:new_from_mem(p.data, ETH_HDR_SIZE)
    local output = self.output.wire
    local ether_type = eth_header:type()
    -- destination mac is assumed empty when it comes from lwaftr
    if self.next_hop_mac then
      local current_time = tonumber(app.now())
      if current_time > self.cache_refresh_time + self.cache_refresh_interval then
        self.cache_refresh_time = current_time
        send_cache_trigger(self.output.vmx, packet.clone(p), self.mac_address)
      end
      -- set nh mac and send the packet out the wire 
      eth_header:dst(self.next_hop_mac)
    else
      -- need to resolve nh. Punch plus a cache trigger to vmx
      send_cache_trigger(self.output.vmx, packet.clone(p), self.mac_address)
      eth_header:dst(self.mac_address)
      output = self.output.vmx
    end
    -- set local source mac address
    eth_header:src(self.mac_address)

    if output and not link.full(output) then
      link.transmit(output, p)
    else
      packet.free(p)
    end
  end

  -- packets from vmx
  if self.input.vmx then
    local input = self.input.vmx
    for n = 1,link.nreadable(input) do
      local p = link.receive(input)
      local eth_header = ethernet:new_from_mem(p.data, ETH_HDR_SIZE)
      local output = self.output.wire
      local ether_type = eth_header:type()
      if self.service_mac and eth_header:dst_eq(self.service_mac) then
        output = self.output.lwaftr
      else
        -- learn nh mac
        if self.cache_refresh_interval > 0 then
          local learn = nil
          if 0x86dd == ether_type then
            local ipv6_header = ipv6:new_from_mem(p.data + ETH_HDR_SIZE, IPV6_HDR_SIZE) 
            if ipv6_header:src_eq(ipv6:pton('fe80::')) and 0x04 == ipv6_header:next_header() then
              learn = "ipv6"
            end
          end
          if 0x0800 == ether_type then
            local ipv4_header = ipv4:new_from_mem(p.data + ETH_HDR_SIZE, IPV4_HDR_SIZE) 
            if ipv4_header:src_eq(ipv4:pton('0.0.0.0')) then
              learn = "ipv4"
            end
          end
          if learn then
            local mac = eth_header:dst()
            if not eth_header:is_mcast(mac) then
              self.next_hop_mac = ethernet:pton("00:00:00:00:00:00")
              ffi.copy(self.next_hop_mac, eth_header:dst(), 6)
              print("learning " .. learn .. " nh mac address " .. ethernet:ntop(self.next_hop_mac))
              -- make sure we free this packe without sending it, this was
              -- a self created packet to learn the nh only
              output = nil 
            end
          end
        end

      end

      if output and not link.full(output) then
        link.transmit(output, p)
      else
        packet.free(p)
      end
    end
  end

end
