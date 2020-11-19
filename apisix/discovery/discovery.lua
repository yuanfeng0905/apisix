--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local local_conf         = require("apisix.core.config_local").local_conf()
local http               = require("resty.http")
local core               = require("apisix.core")
local ipmatcher          = require("resty.ipmatcher")
local ipairs             = ipairs
local string             = string
local tostring           = tostring
local type               = type
local math_random        = math.random
local error              = error
local ngx                = ngx
local ngx_timer_at       = ngx.timer.at
local ngx_timer_every    = ngx.timer.every
local string_sub         = string.sub
local string_find        = string.find
local log                = core.log

local default_weight
local applications

local schema = {
    type = "object",
    properties = {
        host = {
            type = "array",
            minItems = 1,
            items = {
                type = "string",
            },
        },
        fetch_interval = {type = "integer", minimum = 1, default = 30},
        prefix = {type = "string"},
        weight = {type = "integer", minimum = 0},
        timeout = {
            type = "object",
            properties = {
                connect = {type = "integer", minimum = 1, default = 2000},
                send = {type = "integer", minimum = 1, default = 2000},
                read = {type = "integer", minimum = 1, default = 5000},
            }
        },
    },
    required = {"host"}
}


local _M = {
    version = 0.1,
}


local function service_info()
    local host = local_conf.discovery and
        local_conf.discovery.discovery and local_conf.discovery.discovery.host
    if not host then
        log.error("do not set discovery.host")
        return
    end

    local basic_auth
    -- TODO Add health check to get healthy nodes.
    -- 随机从host池取一个链接
    local url = host[math_random(#host)]
    local auth_idx = string_find(url, "@", 1, true)
    if auth_idx then
        local protocol_idx = string_find(url, "://", 1, true)
        local protocol = string_sub(url, 1, protocol_idx + 2)
        local user_and_password = string_sub(url, protocol_idx + 3, auth_idx - 1)
        local other = string_sub(url, auth_idx + 1)
        url = protocol .. other
        basic_auth = "Basic " .. ngx.encode_base64(user_and_password)
    end
    if local_conf.discovery.discovery.prefix then
        url = url .. local_conf.discovery.discovery.prefix
    end
    if string_sub(url, #url) ~= "/" then
        url = url .. "/"
    end

    return url, basic_auth
end


local function request(request_uri, basic_auth, method, path, query, body)
    log.info("discovery uri:", request_uri, ".")
    local url = request_uri .. path
    local headers = core.table.new(0, 5)
    headers['Connection'] = 'Keep-Alive'
    headers['Accept'] = 'application/json'

    if basic_auth then
        headers['Authorization'] = basic_auth
    end

    if body and 'table' == type(body) then
        local err
        body, err = core.json.encode(body)
        if not body then
            return nil, 'invalid body : ' .. err
        end
        -- log.warn(method, url, body)
        headers['Content-Type'] = 'application/json'
    end

    local httpc = http.new()
    local timeout = local_conf.discovery.discovery.timeout
    local connect_timeout = timeout and timeout.connect or 2000
    local send_timeout = timeout and timeout.send or 2000
    local read_timeout = timeout and timeout.read or 5000
    log.info("connect_timeout:", connect_timeout, ", send_timeout:", send_timeout,
            ", read_timeout:", read_timeout, ".")
    httpc:set_timeouts(connect_timeout, send_timeout, read_timeout)
    return httpc:request_uri(url, {
        version = 1.1,
        method = method,
        headers = headers,
        query = query,
        body = body,
        ssl_verify = false,
    })
end


local function parse_instance(instance)
    local status = instance.status
    -- 只选择正常流量节点
    if status ~= 1 then
        return
    end

    local port, ip
    local addrs = instance.addrs
    for _, addr in ipairs(addrs) do
        -- 只支持http协议
        local sp = string.find(addr, "http://", 1, true)
        if sp then
            local ip_port = string.sub(addr, 8)
            -- 分隔IP/Port
            local sp1 = string.find(ip_port, ":", 1, true)
            if sp1 then
                ip = string.sub(ip_port, 1, sp1-1)
                port = string.sub(ip_port, sp1+1, -1)
            end
        end
    end
    if not ipmatcher.parse_ipv4(ip) and
            not ipmatcher.parse_ipv6(ip) then
        log.error(instance.appid, " service node IP ", ip,
                " is invalid(must be IPv4 or IPv6).")
        return
    end
    -- metdata 空数据处理
    local metadata = tostring(instance.metadata) == 'NULL' or {}
    log.info("appid=", instance.appid, " ip=", ip, " port=", port, " type(metadata)=", type(metadata))
    return ip, port, metadata
end


local function fetch_full_registry(premature)
    if premature then
        return
    end

    local request_uri, basic_auth = service_info()
    if not request_uri then
        return
    end

    -- 拉取所有应用信息
    local res, err = request(request_uri, basic_auth, "GET", "discovery/fetch/all")
    if not res then
        log.error("failed to fetch registry", err)
        return
    end

    if not res.body or res.status ~= 200 then
        log.error("failed to fetch registry, status = ", res.status)
        return
    end

    local json_str = res.body
    local data, err = core.json.decode(json_str)
    if not data then
        log.error("invalid response body: ", json_str, " err: ", err)
        return
    end
    if data.code ~= 0 then
        log.error("response code: ", data.code, "err: ", data.message)
        return
    end

    local apps = data.data
    local up_apps = core.table.new(0, #apps)
    for app, instances in pairs(apps) do
        for _, instance in ipairs(instances) do
            local ip, port, md = parse_instance(instance)
            if ip and port then
                local nodes = up_apps[app]
                if not nodes then
                    nodes = core.table.new(#instances, 0)
                    up_apps[app] = nodes
                end
                core.table.insert(nodes, {
                    host = ip,
                    port = port,
                    weight = md and md.weight or default_weight,
                    metadata = md,
                })
                if md then
                    -- remove useless data
                    md.weight = nil
                end
            end
        end
    end
    applications = up_apps
end


function _M.nodes(service_name)
    if not applications then
        log.error("failed to fetch nodes for : ", service_name)
        return
    end

    return applications[service_name]
end


function _M.init_worker()
    if not local_conf.discovery.discovery or
        not local_conf.discovery.discovery.host or #local_conf.discovery.discovery.host == 0 then
        error("do not set discovery.host")
        return
    end

    local ok, err = core.schema.check(schema, local_conf.discovery.discovery)
    if not ok then
        error("invalid discovery configuration: " .. err)
        return
    end
    default_weight = local_conf.discovery.discovery.weight or 100
    log.info("default_weight:", default_weight, ".")
    local fetch_interval = local_conf.discovery.discovery.fetch_interval or 30
    log.info("fetch_interval:", fetch_interval, ".")
    ngx_timer_at(0, fetch_full_registry)
    ngx_timer_every(fetch_interval, fetch_full_registry)
end


return _M
