module(..., package.seeall)

local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local lwutil = require("apps.lwaftr.lwutil")
local bt = require("apps.lwaftr.binding_table")
local dump = require("apps.lwaftr.dump")

policies = {
  DROP = 1,
  ALLOW = 2
}

local aftrconf = {}

local function split (str, sep)
  local t = {}
  local regex = ("([^%s]+)"):format(sep)
  for each in str:gmatch(regex) do
    table.insert(t, each)
  end
  return t
end

function ssh_read_conf(host, identity, group)
  local command = "ssh -o StrictHostKeyChecking=no -i " .. identity .. " " .. host .. " show conf groups " .. group
  local conf = {}
  local ssh = io.popen(command)
  while true do
    local line = ssh:read()
    if line == nil then break end
  --  print("line=" .. line)
    -- break junos 'parameter value;' into key and value
    -- some parameters don't have a value at all
    local key, value = string.match(line, "([%w:_]+)[%s;]([%w.:,_]*)") 
    if key == "ipv6_address" then
      conf[key] = ipv6:pton(value)
    elseif key == "ipv4_address" then
      conf[key] = ipv4:pton(value) 
    elseif string.match(key,":") then
      -- IPv6 key, value used for binding_table
      local entry = split(value,",")
      if #entry == 3 then
        local b4_v6 = ipv6:pton(key)
        local pv4 = lwutil.rd32(ipv4:pton(entry[1]))
        local port_begin = tonumber(entry[2])
        local port_end = tonumber(entry[3])
        local pentry = {b4_v6, pv4, port_begin, port_end}
        table.insert(conf, pentry)
      else
        print("bogus binding_table entry: " .. line)
      end
    elseif string.match(key,"policy_") then
      local drop_or_allow = value:upper()
      conf[key] = policies[drop_or_allow]
    elseif string.match(key,"_packets") then
      conf[key] = tonumber(value)
    elseif string.match(key,"_seconds") then
      conf[key] = tonumber(value)
    elseif string.match(key,"mtu") then
      conf[key] = tonumber(value)
    elseif value then
      conf[key] = value
    else
      conf[key] = true
    end
  end
  ssh:close()
  return conf
end

function get_aftrconf(v6_port, v4_port, ip, user, identity)

  local host = user .. "@" .. ip
  local group = "lwaftr-" .. v6_port .. "-" .. v4_port

  -- read global settings, then fill in defaults when missing
  aftrconf = ssh_read_conf(host, identity, group .. " apply-macro settings")
  aftrconf.hairpinning = aftrconf.hairpinning or false
  aftrconf.icmpv6_rate_limiter_n_packets = aftrconf.icmpv6_rate_limiter_n_packets or 6e5
  aftrconf.icmpv6_rate_limiter_n_seconds = aftrconf.icmpv6_rate_limiter_n_seconds or 2
  aftrconf.policy_icmpv4_incoming = aftrconf.policy_icmpv4_incoming or policies['ALLOW']
  aftrconf.policy_icmpv6_incoming = aftrconf.policy_icmpv6_incoming or policies['ALLOW']
  aftrconf.policy_icmpv4_outgoing = aftrconf.policy_icmpv4_outgoing or policies['ALLOW']
  aftrconf.policy_icmpv6_outgoing = aftrconf.policy_icmpv6_outgoing or policies['ALLOW']

  -- read interfaces and binding tables
  aftrconf.ipv6_interface = ssh_read_conf(host, identity, group .. " apply-macro ipv6_interface")
  aftrconf.ipv4_interface = ssh_read_conf(host, identity, group .. " apply-macro ipv4_interface")
  aftrconf.binding_table = ssh_read_conf(host, identity, group .. " apply-macro binding_table")

  -- ethernet mac addresses are just set to keep lwaftr happy. 
  -- actual mac addresses are handled by nh_fwd app
  aftrconf.aftr_mac_b4_side = ethernet:pton("22:22:22:22:22:22")
  aftrconf.aftr_mac_inet_side = ethernet:pton("12:12:12:12:12:12")
  aftrconf.b4_mac = ethernet:pton("44:44:44:44:44:44")
  aftrconf.inet_mac = ethernet:pton("68:68:68:68:68:68")

  -- using ipv4/6 addresses and mtu from the interface group for lwaftr
  -- these stanza's are primarly required for nh_fwd
  aftrconf.aftr_ipv4_ip = aftrconf.ipv4_interface.ipv4_address
  aftrconf.aftr_ipv6_ip = aftrconf.ipv6_interface.ipv6_address
  aftrconf.ipv4_mtu = aftrconf.ipv4_interface.mtu or 1460
  aftrconf.ipv6_mtu = aftrconf.ipv6_interface.mtu or 1500
  
  return aftrconf
end
