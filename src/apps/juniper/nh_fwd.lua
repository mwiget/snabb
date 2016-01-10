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


--- # `nh_fwd` app: Finds next hop mac by sending packets to VM interface

nh_fwd = {}

function nh_fwd:new(arg)
  local conf = arg and config.parse_app_arg(arg) or {}
  local mac_address = ethernet:pton(conf.mac_address)
  local ipv6_address = conf.ipv6_address
  local ipv4_address = conf.ipv4_address
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
      local output = self.output.vmx
      local ether_type = eth_header:type()
      local dstmac = eth_header:dst()
      if eth_header:is_mcast(mac) then
        output = self.output.vmx
      elseif eth_header:dst_eq(self.mac_address) then
        if 0x0800 == ether_type and p.length > ETH_HDR_SIZE + IPV4_HDR_SIZE then
          -- IPv4 packet from wire
          local ipv4_header = ipv4:new_from_mem(p.data + ETH_HDR_SIZE, IPV4_HDR_SIZE) 
          output = self.output.lwaftr
          if self.ipv4_address and ipv4_header:dst_eq(self.ipv4_address) then
            -- local IPv4 destination to vMX, else to lwaftr
            output = self.output.vmx
          end
        elseif 0x86dd == ether_type and p.length > ETH_HDR_SIZE + IPV6_HDR_SIZE and self.ipv6_address then
          -- IPv6 packet from wire
          local ipv6_header = ipv6:new_from_mem(p.data + ETH_HDR_SIZE, IPV6_HDR_SIZE) 
          if 0x04 == ipv6_header:next_header() then
            output = self.output.lwaftr
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
        eth_header:dst(self.mac_address)
        output = self.output.vmx
      else
        -- set nh mac and send the packet out the wire 
        eth_header:dst(self.next_hop_mac)
      end
    else
      -- need to resolve nh. Punch it to vmx
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
            -- check for IPIP next header. Only use those packets for
            -- nh learning
            if 0x04 == ipv6_header:next_header() then
              learn = "ipv6"
            end
          end
          if 0x0800 == ether_type then
            learn = "ipv4"
          end
          if learn then
            local mac = eth_header:dst()
            if not eth_header:is_mcast(mac) then
              self.next_hop_mac = ethernet:pton("00:00:00:00:00:00")
              ffi.copy(self.next_hop_mac, eth_header:dst(), 6)
              print("learning " .. learn .. " nh mac address " .. ethernet:ntop(self.next_hop_mac))
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
