module("luci.controller.admin.wifi_monitor", package.seeall)

function index()
    entry({"admin", "status", "wifi_monitor"}, template("admin_status/wifi_monitor"), _("无线终端监控"), 60)
    entry({"admin", "status", "wifi_acl"}, call("wifi_acl")).leaf = true
    entry({"admin", "status", "wifi_json"}, call("wifi_json")).leaf = true
    entry({"admin", "status", "vendor_lookup"}, call("vendor_lookup")).leaf = true
    entry({"admin", "status", "wifi_router"}, call("wifi_router")).leaf = true
    entry({"admin", "status", "wifi_router_set"}, call("wifi_router_set")).leaf = true
    entry({"admin", "status", "wifi_monitor_config"}, call("wifi_monitor_config")).leaf = true
    entry({"admin", "status", "wifi_restart"}, call("wifi_restart")).leaf = true
    entry({"admin", "status", "router_reboot"}, call("router_reboot")).leaf = true
end

local http = require "luci.http"
local jsonc = require "luci.jsonc"
local util = require "luci.util"
local fs = require "nixio.fs"
local uci = require "luci.model.uci".cursor()

local MI_IP = (uci and uci:get("wifi_monitor", "main", "mi_ip")) or "192.168.10.10"
local ACL_FILE = "/etc/config/wifi_ACLlist"
local IFACE_WL0 = "wl0"
local IFACE_WL1 = "wl1"

local SSH_BIN = nil
local SSH_OPTS = nil
local SSH_LAST_OUT = ""

local function init_ssh()
    if SSH_BIN then return end
    if fs.access("/usr/bin/ssh", "x") then
        SSH_BIN = "/usr/bin/ssh"
    else
        SSH_BIN = "ssh"
    end
    SSH_OPTS = "-o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
end

local function ssh_prefix()
    init_ssh()
    return SSH_BIN .. " " .. SSH_OPTS
end

local function map_iface(band)
    if band == "wl0" then return IFACE_WL0 end
    if band == "wl1" then return IFACE_WL1 end
    return band
end

local function sanitize_field(s)
    if not s then return "" end
    s = s:gsub("[\r\n|]", "")
    return s
end

local function find_script(name)
    local candidates = {
        "/usr/libexec/wifi/" .. name,
        "/www/cgi-bin/" .. name,
        "/cgi-bin/" .. name
    }
    for _, p in ipairs(candidates) do
        if fs.access(p, "x") then
            return p
        end
    end
    return nil
end

local function exec_cgi(path, qs)
    if qs and qs ~= "" then
        local cmd = "QUERY_STRING=" .. util.shellquote(qs) .. " " .. util.shellquote(path)
        return luci.sys.exec(cmd)
    end
    return luci.sys.exec(util.shellquote(path))
end

local function strip_headers(out)
    if not out then return "" end
    out = out:gsub("^Content%-type:[^\n]*\r?\n\r?\n", "")
    return out
end

local function normalize_mac(mac)
    if not mac then return "" end
    return mac:upper()
end

local function mac_valid(mac)
    return mac and mac:match("^[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]$") ~= nil
end

local function read_lines()
    local lines = {}
    local f = io.open(ACL_FILE, "r")
    if not f then return lines end
    for line in f:lines() do
        if line and line ~= "" then
            table.insert(lines, line)
        end
    end
    f:close()
    return lines
end

local function write_lines(lines)
    local f = io.open(ACL_FILE, "w")
    if not f then return false end
    for _, line in ipairs(lines) do
        f:write(line, "\n")
    end
    f:close()
    return true
end

local function parse_line(line)
    local parts = util.split(line, "|")
    return parts[1], parts[2], parts[3] or "", parts[4] or ""
end

local function list_acl()
    local wl0, wl1 = {}, {}
    local lines = read_lines()
    for _, line in ipairs(lines) do
        local band, mac, name, ip = parse_line(line)
        if band and mac then
            local entry = { mac = normalize_mac(mac), name = name or "", ip = ip or "" }
            if band == "wl0" then
                table.insert(wl0, entry)
            elseif band == "wl1" then
                table.insert(wl1, entry)
            end
        end
    end
    return { wl0 = wl0, wl1 = wl1 }
end

local function band_has_entries(lines, band)
    for _, line in ipairs(lines) do
        local b, _ = parse_line(line)
        if b == band then return true end
    end
    return false
end

local function ssh_exec(cmd)
    local full = string.format("%s root@%s \"%s\"", ssh_prefix(), MI_IP, cmd)
    local out = luci.sys.exec(full .. " 2>&1; echo __RC__$?") or ""
    SSH_LAST_OUT = out
    local rc = tonumber(out:match("__RC__(%d+)") or "") or 1
    return rc == 0
end

local function ssh_capture(cmd)
    local full = string.format("%s root@%s \"%s\"", ssh_prefix(), MI_IP, cmd)
    return luci.sys.exec(full) or ""
end

local function ssh_capture_raw(cmd)
    local full = string.format("%s root@%s \"%s\"", ssh_prefix(), MI_IP, cmd)
    return luci.sys.exec(full .. " 2>&1") or ""
end

local function trim(s)
    if not s then return "" end
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function ssh_last_err()
    local out = SSH_LAST_OUT or ""
    out = out:gsub("__RC__%d+", "")
    out = trim(out)
    if #out > 200 then
        out = out:sub(1, 200) .. "..."
    end
    return out
end

local function format_ssh_error(out)
    local err = out or ssh_last_err()
    err = err:gsub("__RC__%d+", "")
    err = trim(err)
    if #err > 200 then
        err = err:sub(1, 200) .. "..."
    end
    if err ~= "" then
        return "ssh failed: " .. err
    end
    return "ssh failed"
end

local function remote_get(path)
    if not path or path == "" then return "" end
    local out = ssh_capture("uci -q get " .. path .. " 2>/dev/null")
    return trim(out)
end

local function valid_section(name, allow_at)
    if not name then return false end
    if name:match("^[%w_\%-]+$") then return true end
    if allow_at and name:match("^@wifi%-iface%[%d+%]$") then return true end
    return false
end

local function do_ban(band, mac, name, ip)
    local iface = map_iface(band)
    local cmd = string.format("iwpriv %s set AccessPolicy=2; iwpriv %s set ACLAddEntry=\\\"%s\\\"; iwpriv %s set AccessPolicy=2", iface, iface, mac, iface)
    local ok = ssh_exec(cmd)
    if not ok then return false end

    local lines = read_lines()
    local exists = false
    for _, line in ipairs(lines) do
        local b, m = parse_line(line)
        if b == band and normalize_mac(m) == mac then
            exists = true
            break
        end
    end
    if not exists then
        table.insert(lines, table.concat({ band, mac, name, ip }, "|"))
        write_lines(lines)
    end
    return true
end

local function do_unban(band, mac)
    local iface = map_iface(band)
    local cmd = string.format("iwpriv %s set ACLDelEntry=\\\"%s\\\"", iface, mac)
    local ok = ssh_exec(cmd)
    if not ok then return false end

    local lines = read_lines()
    local new_lines = {}
    for _, line in ipairs(lines) do
        local b, m = parse_line(line)
        if not (b == band and normalize_mac(m) == mac) then
            table.insert(new_lines, line)
        end
    end
    write_lines(new_lines)

    if not band_has_entries(new_lines, band) then
        ssh_exec(string.format("iwpriv %s set AccessPolicy=0", iface))
    else
        ssh_exec(string.format("iwpriv %s set AccessPolicy=2", iface))
    end
    return true
end

function wifi_acl()
    http.prepare_content("application/json")
    local action = http.formvalue("action") or ""
    if action == "" then
        http.write(jsonc.stringify({ ok = false, error = "missing action" }))
        return
    end

    if action == "list" then
        http.write(jsonc.stringify(list_acl()))
        return
    end

    local mac = normalize_mac(http.formvalue("mac") or "")
    local bands = http.formvalue("bands") or "both"
    local name = sanitize_field(http.formvalue("name") or "")
    local ip = sanitize_field(http.formvalue("ip") or "")

    if not mac_valid(mac) then
        http.write(jsonc.stringify({ ok = false, error = "invalid mac" }))
        return
    end

    local target_bands = {}
    if bands == "wl0" or bands == "wl1" then
        target_bands = { bands }
    else
        target_bands = { "wl0", "wl1" }
    end

    for _, band in ipairs(target_bands) do
        if action == "ban" then
            if not do_ban(band, mac, name, ip) then
                http.write(jsonc.stringify({ ok = false, error = format_ssh_error(nil), band = band }))
                return
            end
        elseif action == "unban" then
            if not do_unban(band, mac) then
                http.write(jsonc.stringify({ ok = false, error = format_ssh_error(nil), band = band }))
                return
            end
        else
            http.write(jsonc.stringify({ ok = false, error = "unknown action" }))
            return
        end
    end

    http.write(jsonc.stringify({ ok = true }))
end

function wifi_json()
    http.prepare_content("application/json")
    local path = find_script("api_wifi_json")
    if not path then
        http.write(jsonc.stringify({ error = "missing api_wifi_json" }))
        return
    end
    local out = exec_cgi(path)
    out = strip_headers(out)
    http.write(out)
end

function vendor_lookup()
    http.prepare_content("text/plain")
    local mac = http.formvalue("mac") or ""
    local path = find_script("get_vendor")
    if not path then
        http.write("ERROR: missing get_vendor")
        return
    end
    local out = exec_cgi(path, "mac=" .. mac)
    out = strip_headers(out)
    http.write(out)
end

local function parse_custom_from_uci(uci_raw)
    local types, opts = {}, {}
    for line in (uci_raw or ""):gmatch("[^\r\n]+") do
        local sec, t = line:match("^wireless\.([^=]+)=(.+)$")
        if sec and t then
            types[sec] = t
        else
            local s, opt, val = line:match("^wireless\.([^.]+)\.([^=]+)=(.+)$")
            if s and opt then
                val = trim(val or ""):gsub("^'", ""):gsub("'$", "")
                if not opts[s] then opts[s] = {} end
                opts[s][opt] = val
            end
        end
    end

    local custom = {}
    for s, o in pairs(opts) do
        if (types[s] == "wifi-iface" or o.mode or o.ssid) and o.mode == "ap" then
            local ifn = o.ifname or ""
            if ifn ~= "wl0" and ifn ~= "wl1" then
                local vifn = tonumber(o.vifidx or "")
                local is_custom = (vifn and vifn >= 7) or (o.custom_ssid == "1")
                if is_custom then
                    local dev = o.device or ""
                    local devopts = opts[dev] or {}
                    local band = devopts.band or ""
                    table.insert(custom, {
                        section = s,
                        ifname = (ifn ~= "") and ifn or nil,
                        ssid = o.ssid or "",
                        band = band,
                        disabled = (o.disabled ~= nil and tonumber(o.disabled)) or nil,
                        hidden = (o.hidden ~= nil and tonumber(o.hidden)) or nil,
                        encryption = o.encryption or "",
                        vifidx = vifn,
                        noforwarding = (o.NoForwarding ~= nil and tonumber(o.NoForwarding)) or nil,
                        wpsdevicename = o.wpsdevicename or "",
                        mbssmaxstanum = (o.MbssMaxStaNum and tonumber(o.MbssMaxStaNum)) or nil,
                        wmm = (o.wmm and tonumber(o.wmm)) or nil,
                        igmpsnenable = (o.IgmpSnEnable and tonumber(o.IgmpSnEnable)) or nil,
                        rrm = (o.rrm and tonumber(o.rrm)) or nil,
                        wnm = (o.wnm and tonumber(o.wnm)) or nil,
                        bsd = (o.bsd and tonumber(o.bsd)) or nil,
                        map = (o.map and tonumber(o.map)) or nil,
                        mapbsstype = (o.MapBSSType and tonumber(o.MapBSSType)) or nil,
                        macfilter = o.macfilter or ""
                    })
                end
            end
        end
    end
    return custom
end

function wifi_monitor_config()
    http.prepare_content("application/json")
    local save = http.formvalue("save") == "1"
    local mi_ip = sanitize_field(http.formvalue("mi_ip") or "")
    local api_key = sanitize_field(http.formvalue("api_key") or "")

    if not uci:get("wifi_monitor", "main") then
        uci:section("wifi_monitor", "wifi_monitor", "main", {})
    end

    if save then
        if mi_ip ~= "" then
            uci:set("wifi_monitor", "main", "mi_ip", mi_ip)
        end
        uci:set("wifi_monitor", "main", "api_key", api_key)
        uci:commit("wifi_monitor")
    end

    local cur_ip = uci:get("wifi_monitor", "main", "mi_ip") or ""
    local cur_key = uci:get("wifi_monitor", "main", "api_key") or ""
    http.write(jsonc.stringify({ ok = true, mi_ip = cur_ip, api_key = cur_key }))
end

function wifi_router()
    http.prepare_content("application/json")
    local path = find_script("api_wifi_router")
    if not path then
        http.write(jsonc.stringify({ ok = false, error = "missing api_wifi_router" }))
        return
    end
    local out = exec_cgi(path)
    out = strip_headers(out)
    local data = jsonc.parse(out)
    if data and data.ok and data.extras and data.extras.custom and #data.extras.custom == 0 then
        local uci_raw = ssh_capture("uci show wireless")
        local custom = parse_custom_from_uci(uci_raw)
        if custom and #custom > 0 then
            data.extras.custom = custom
            out = jsonc.stringify(data)
        end
    end
    http.write(out)
end

function wifi_router_set()
    http.prepare_content("application/json")
    local section = http.formvalue("section") or ""
    local band = http.formvalue("band") or ""
    local debug = http.formvalue("debug") == "1"
    local ssid = sanitize_field(http.formvalue("ssid") or "")
    local key = sanitize_field(http.formvalue("key") or "")
    local enable = http.formvalue("enable")
    local radio = http.formvalue("radio")
    local channel = http.formvalue("channel")
    local bw = http.formvalue("bw")
    local txpwr = http.formvalue("txpwr")
    local hidden = http.formvalue("hidden")
    local encryption = http.formvalue("encryption") or ""
    local bsd = http.formvalue("bsd")
    local dfs = http.formvalue("dfs")
    local country = sanitize_field(http.formvalue("country") or "")
    local ax = http.formvalue("ax")
    local txbf = http.formvalue("txbf")
    local mesh = http.formvalue("mesh")
    local custom = http.formvalue("custom") or ""
    local req_ifname = ""
    local req_vifidx = tonumber(http.formvalue("vifidx") or "")
    local noforwarding = http.formvalue("noforwarding")
    local wpsdevicename = sanitize_field(http.formvalue("wpsdevicename") or "")
    local mbssmaxstanum = http.formvalue("mbssmaxstanum")
    local wmm = http.formvalue("wmm")
    local igmpsnenable = http.formvalue("igmpsnenable")
    local rrm = http.formvalue("rrm")
    local wnm = http.formvalue("wnm")
    local map = http.formvalue("map")
    local mapbsstype = http.formvalue("mapbsstype")
    local macfilter = http.formvalue("macfilter")

    local function json_error(msg)
        http.write(jsonc.stringify({ ok = false, error = msg }))
    end

    local function q(val)
        return util.shellquote(val or "")
    end

    local function run_remote(cmds)
        if #cmds == 0 then return true, "" end
        local out = ssh_capture_raw(table.concat(cmds, "; ") .. "; echo __RC__$?")
        local rc = tonumber(out:match("__RC__(%d+)") or "") or 1
        return rc == 0, out
    end

    if custom == "add" then
        if band ~= "wl0" and band ~= "wl1" then
            json_error("invalid band")
            return
        end
        if ssid == "" then
            json_error("missing ssid")
            return
        end
        local dev = remote_get("wireless." .. band .. ".device")
        if dev == "" then
            json_error("missing device")
            return
        end
        local net = remote_get("wireless." .. band .. ".network")
        if net == "" then net = "lan" end
        local function valid_ifname(name)
            return name and name:match("^wl%d+$") ~= nil
        end

        local function collect_vifidx(devname)
            local out = ssh_capture("uci show wireless")
            local types, opts = {}, {}
            for line in (out or ""):gmatch("[^\r\n]+") do
                local sec, t = line:match("^wireless%.([^=]+)=(.+)$")
                if sec and t then
                    types[sec] = t
                else
                    local s, opt, val = line:match("^wireless%.([^.]+)%.([^=]+)=(.+)$")
                    if s and opt then
                        val = trim(val or "")
                        val = val:gsub("^'", ""):gsub("'$", "")
                        if not opts[s] then opts[s] = {} end
                        opts[s][opt] = val
                    end
                end
            end
            local used = {}
            for sec, o in pairs(opts) do
                if types[sec] == "wifi-iface" and o.device == devname then
                    local v = tonumber(o.vifidx or "")
                    if v then used[v] = true end
                end
            end
            return used
        end

        local function list_vifidx(used)
            local list = {}
            for v in pairs(used or {}) do
                table.insert(list, v)
            end
            table.sort(list)
            return list
        end

        local function pick_vifidx(used)
            local idx = 7
            while used[idx] do idx = idx + 1 end
            return idx
        end

        local function pick_ifname()
            local out = ssh_capture("iwinfo 2>/dev/null | awk '$2==\"ESSID:\" {print $1}'")
            local used = {}
            local maxn = -1
            for line in (out or ""):gmatch("[^\r\n]+") do
                line = trim(line)
                if line ~= "" then
                    used[line] = true
                    local n = line:match("^wl(%d+)$")
                    if n then
                        local nn = tonumber(n)
                        if nn and nn > maxn then maxn = nn end
                    end
                end
            end
            local out2 = ssh_capture("uci show wireless")
            for line in (out2 or ""):gmatch("[^\r\n]+") do
                local ifn = line:match("^wireless%.[^.]+%.ifname=(.+)$")
                if ifn then
                    ifn = trim(ifn or ""):gsub("^'", ""):gsub("'$", "")
                    if ifn ~= "" then
                        used[ifn] = true
                        local n = ifn:match("^wl(%d+)$")
                        if n then
                            local nn = tonumber(n)
                            if nn and nn > maxn then maxn = nn end
                        end
                    end
                end
            end
            for i = 0, maxn + 8 do
                local cand = "wl" .. tostring(i)
                if not used[cand] then
                    return cand
                end
            end
            return "wl" .. tostring(maxn + 1)
        end

        local function ssid_exists(target)
            if target == "" then return false end
            local iflist = ssh_capture("iwinfo 2>/dev/null | awk '$2==\"ESSID:\" {print $1}'")
            for line in (iflist or ""):gmatch("[^\r\n]+") do
                local ifn = trim(line)
                if ifn ~= "" then
                    local info = ssh_capture("iwinfo " .. q(ifn) .. " info 2>/dev/null")
                    for l in (info or ""):gmatch("[^\r\n]+") do
                        local essid = l:match("^%s*ESSID:%s*\"?(.-)\"?$")
                        if essid and trim(essid) == target then
                            return true
                        end
                    end
                end
            end
            return false
        end

        local new_ifname = pick_ifname()

        local used_vif = collect_vifidx(dev)
        local use_vifidx = nil
        if req_vifidx then
            if req_vifidx < 7 then
                json_error("vifidx must be >= 7")
                return
            end
            if used_vif[req_vifidx] then
                local list = list_vifidx(used_vif)
                json_error("vifidx already used, used=" .. table.concat(list, ","))
                return
            end
            use_vifidx = req_vifidx
        else
            use_vifidx = pick_vifidx(used_vif)
        end

        local newsec = trim(ssh_capture("uci add wireless wifi-iface"))
        if newsec == "" or not valid_section(newsec) then
            json_error("create failed")
            return
        end
        local function norm01(val, def)
            if val == "1" or val == "0" then return val end
            return def
        end
        local function normnum(val, def)
            if val and tostring(val):match("^%d+$") then return tostring(val) end
            return def
        end
        local function normmacfilter(val)
            if val == "allow" or val == "deny" or val == "disabled" then return val end
            return "disabled"
        end

        local nof = norm01(noforwarding, "0")
        local wmm_v = norm01(wmm, "1")
        local igmp_v = norm01(igmpsnenable, "1")
        local rrm_v = norm01(rrm, "1")
        local wnm_v = norm01(wnm, "1")
        local bsd_v = norm01(bsd, "1")
        local map_v = norm01(map, "0")
        local mbss_v = normnum(mbssmaxstanum, "64")
        local mapbsstype_v = normnum(mapbsstype, "32")
        local macfilter_v = normmacfilter(macfilter)
        local wpsname_v = wpsdevicename ~= "" and wpsdevicename or "XIAOMI_ROUTER_GUEST"

        local cmds = {
            "uci set wireless." .. newsec .. ".device=" .. q(dev),
            "uci set wireless." .. newsec .. ".mode=" .. q("ap"),
            "uci set wireless." .. newsec .. ".network=" .. q(net),
            "uci set wireless." .. newsec .. ".ssid=" .. q(ssid),
            "uci set wireless." .. newsec .. ".custom_ssid=" .. q("1"),
            "uci set wireless." .. newsec .. ".vifidx=" .. q(tostring(use_vifidx))
        }
        if new_ifname ~= "" then
            table.insert(cmds, "uci set wireless." .. newsec .. ".ifname=" .. q(new_ifname))
        end
        table.insert(cmds, "uci set wireless." .. newsec .. ".NoForwarding=" .. q(nof))
        table.insert(cmds, "uci set wireless." .. newsec .. ".wpsdevicename=" .. q(wpsname_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".MbssMaxStaNum=" .. q(mbss_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".wmm=" .. q(wmm_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".IgmpSnEnable=" .. q(igmp_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".rrm=" .. q(rrm_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".wnm=" .. q(wnm_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".bsd=" .. q(bsd_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".map=" .. q(map_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".MapBSSType=" .. q(mapbsstype_v))
        table.insert(cmds, "uci set wireless." .. newsec .. ".macfilter=" .. q(macfilter_v))
        if encryption ~= "" then
            table.insert(cmds, "uci set wireless." .. newsec .. ".encryption=" .. q(encryption))
        end
        if encryption ~= "none" and key ~= "" then
            table.insert(cmds, "uci set wireless." .. newsec .. ".key=" .. q(key))
        end
        if hidden == "1" or hidden == "0" then
            table.insert(cmds, "uci set wireless." .. newsec .. ".hidden=" .. q(hidden))
        end
        if enable == "1" or enable == "0" then
            table.insert(cmds, "uci set wireless." .. newsec .. ".disabled=" .. q((enable == "1") and "0" or "1"))
        else
            table.insert(cmds, "uci set wireless." .. newsec .. ".disabled=" .. q("0"))
        end
        table.insert(cmds, "uci commit wireless")
        table.insert(cmds, "/sbin/wifi restart >/dev/null 2>&1")
        local ok, out = run_remote(cmds)
        if not ok then
            json_error(format_ssh_error(out))
            return
        end
        if new_ifname ~= "" then
            local check = ssh_capture("iwinfo 2>/dev/null | awk '$2==\"ESSID:\" {print $1}'")
            local found = false
            for line in (check or ""):gmatch("[^\r\n]+") do
                if trim(line) == new_ifname then
                    found = true
                    break
                end
            end
            if not found then
                local check2 = ssh_capture("sleep 2; iwinfo 2>/dev/null | awk '$2==\"ESSID:\" {print $1}'")
                for line in (check2 or ""):gmatch("[^\r\n]+") do
                    if trim(line) == new_ifname then
                        found = true
                        break
                    end
                end
                if not found then
                    local ssid_found = ssid_exists(ssid)
                    local cfg_ssid = remote_get("wireless." .. newsec .. ".ssid")
                    local cfg_dis = remote_get("wireless." .. newsec .. ".disabled")
                    local cfg_ok = (cfg_ssid == ssid) and (cfg_dis == "" or cfg_dis == "0")
                    if ssid_found or cfg_ok then
                        if debug then
                            http.write(jsonc.stringify({ ok = true, section = newsec, ifname = new_ifname, vifidx = use_vifidx, warning = "ifname not visible yet, but SSID is active", debug = { cmds = cmds, out = out, iwdev = (check .. "\n" .. (check2 or "")) } }))
                        else
                            http.write(jsonc.stringify({ ok = true, section = newsec, ifname = new_ifname, vifidx = use_vifidx, warning = "ifname not visible yet, but SSID is active" }))
                        end
                        return
                    end
                    if debug then
                        http.write(jsonc.stringify({ ok = true, section = newsec, ifname = new_ifname, vifidx = use_vifidx, warning = "ifname not visible yet; please refresh later", debug = { cmds = cmds, out = out, iwdev = (check .. "\n" .. (check2 or "")) } }))
                    else
                        http.write(jsonc.stringify({ ok = true, section = newsec, ifname = new_ifname, vifidx = use_vifidx, warning = "ifname not visible yet; please refresh later" }))
                    end
                    return
                end
            end
        end
        if debug then
            http.write(jsonc.stringify({ ok = true, section = newsec, ifname = new_ifname ~= "" and new_ifname or nil, vifidx = use_vifidx, debug = { cmds = cmds, out = out } }))
        else
            http.write(jsonc.stringify({ ok = true, section = newsec, ifname = new_ifname ~= "" and new_ifname or nil, vifidx = use_vifidx }))
        end
        return
    elseif custom == "delete" then
        if section == "" or not valid_section(section, true) then
            json_error("invalid section")
            return
        end
        local flag = remote_get("wireless." .. section .. ".custom_ssid")
        local vif = remote_get("wireless." .. section .. ".vifidx")
        local vifn = tonumber(vif or "")
        if flag ~= "1" and not (vifn and vifn >= 7) then
            json_error("not custom")
            return
        end
        local dev = remote_get("wireless." .. section .. ".device")
        local del_cmds = { "uci -q delete wireless." .. section, "uci commit wireless" }
        if dev ~= "" then
            table.insert(del_cmds, "wifi reload " .. q(dev) .. " >/dev/null 2>&1")
        else
            table.insert(del_cmds, "wifi reload MT7981_1_1 >/dev/null 2>&1")
            table.insert(del_cmds, "wifi reload MT7981_1_2 >/dev/null 2>&1")
        end
        local ok, out = run_remote(del_cmds)
        if not ok then
            json_error(format_ssh_error(out))
            return
        end
        if debug then
            http.write(jsonc.stringify({ ok = true, debug = { out = out } }))
        else
            http.write(jsonc.stringify({ ok = true }))
        end
        return
    end

    local ifaces = {}
    if section ~= "" then
        if not valid_section(section, true) then
            http.write(jsonc.stringify({ ok = false, error = "invalid section" }))
            return
        end
        ifaces = { section }
    else
        if band == "wl0" or band == "wl1" then
            ifaces = { band }
        elseif band == "both" then
            ifaces = { "wl0", "wl1" }
        else
            http.write(jsonc.stringify({ ok = false, error = "invalid band" }))
            return
        end
    end

    local cmds = {}
    local devs = {}
    local reload_devs = {}
    local changed = false
    local mesh_changed = false
    for _, b in ipairs(ifaces) do
        local dev = remote_get("wireless." .. b .. ".device")
        if dev == "" then
            json_error("missing device")
            return
        end
        devs[dev] = true
        local devband = remote_get("wireless." .. dev .. ".band")
        local devband_l = (devband or ""):lower()
        local dev_changed = false
        local function add_cmd(cmd)
            table.insert(cmds, cmd)
            dev_changed = true
        end
        if ssid ~= "" then
            add_cmd("uci set wireless." .. b .. ".ssid=" .. q(ssid))
            changed = true
        end
        if key ~= "" then
            add_cmd("uci set wireless." .. b .. ".key=" .. q(key))
            changed = true
        end
        if encryption ~= "" then
            add_cmd("uci set wireless." .. b .. ".encryption=" .. q(encryption))
            changed = true
            if encryption == "none" and key == "" then
                add_cmd("uci set wireless." .. b .. ".key=" .. q(""))
            end
        end
        if hidden == "1" or hidden == "0" then
            add_cmd("uci set wireless." .. b .. ".hidden=" .. q(hidden))
            changed = true
        end
        if enable == "1" or enable == "0" then
            add_cmd("uci set wireless." .. b .. ".disabled=" .. q((enable == "1") and "0" or "1"))
            changed = true
        end
        if bsd == "1" or bsd == "0" then
            add_cmd("uci set wireless." .. b .. ".bsd=" .. q(bsd))
            changed = true
        end
        if noforwarding == "1" or noforwarding == "0" then
            add_cmd("uci set wireless." .. b .. ".NoForwarding=" .. q(noforwarding))
            changed = true
        end
        if wmm == "1" or wmm == "0" then
            add_cmd("uci set wireless." .. b .. ".wmm=" .. q(wmm))
            changed = true
        end
        if igmpsnenable == "1" or igmpsnenable == "0" then
            add_cmd("uci set wireless." .. b .. ".IgmpSnEnable=" .. q(igmpsnenable))
            changed = true
        end
        if rrm == "1" or rrm == "0" then
            add_cmd("uci set wireless." .. b .. ".rrm=" .. q(rrm))
            changed = true
        end
        if wnm == "1" or wnm == "0" then
            add_cmd("uci set wireless." .. b .. ".wnm=" .. q(wnm))
            changed = true
        end
        if map == "1" or map == "0" then
            add_cmd("uci set wireless." .. b .. ".map=" .. q(map))
            changed = true
        end
        if mapbsstype and tostring(mapbsstype):match("^%d+$") then
            add_cmd("uci set wireless." .. b .. ".MapBSSType=" .. q(mapbsstype))
            changed = true
        end
        if mbssmaxstanum and tostring(mbssmaxstanum):match("^%d+$") then
            add_cmd("uci set wireless." .. b .. ".MbssMaxStaNum=" .. q(mbssmaxstanum))
            changed = true
        end
        if macfilter == "allow" or macfilter == "deny" or macfilter == "disabled" then
            add_cmd("uci set wireless." .. b .. ".macfilter=" .. q(macfilter))
            changed = true
        end
        if wpsdevicename ~= "" then
            add_cmd("uci set wireless." .. b .. ".wpsdevicename=" .. q(wpsdevicename))
            changed = true
        end
        if radio == "1" or radio == "0" then
            add_cmd("uci set wireless." .. dev .. ".disabled=" .. q((radio == "1") and "0" or "1"))
            changed = true
        end
        if channel and channel ~= "" then
            add_cmd("uci set wireless." .. dev .. ".channel=" .. q(channel))
            if channel == "0" then
                add_cmd("uci set wireless." .. dev .. ".autoch=" .. q("1"))
            else
                add_cmd("uci set wireless." .. dev .. ".autoch=" .. q("0"))
            end
            changed = true
        end
        if bw and bw ~= "" then
            add_cmd("uci set wireless." .. dev .. ".bw=" .. q(bw))
            changed = true
        end
        if txpwr and txpwr ~= "" then
            add_cmd("uci set wireless." .. dev .. ".txpwr=" .. q(txpwr))
            changed = true
        end
        if country ~= "" then
            if country:match("^[A-Za-z][A-Za-z]$") then
                add_cmd("uci set wireless." .. dev .. ".country=" .. q(country:upper()))
                changed = true
            end
        end
        if ax == "1" or ax == "0" then
            add_cmd("uci set wireless." .. dev .. ".ax=" .. q(ax))
            changed = true
        end
        if txbf == "1" or txbf == "0" then
            add_cmd("uci set wireless." .. dev .. ".txbf=" .. q((txbf == "1") and "3" or "0"))
            changed = true
        end
        if dfs == "1" or dfs == "0" then
            local has_dfs = remote_get("wireless." .. dev .. ".DfsEnable")
            if has_dfs ~= "" or devband_l:find("5") then
                add_cmd("uci set wireless." .. dev .. ".DfsEnable=" .. q(dfs))
                changed = true
            end
        end
        if dev_changed then
            reload_devs[dev] = true
        end
    end

    if mesh == "1" or mesh == "0" then
        table.insert(cmds, "uci set xiaoqiang.common.MESH_SWITCH=" .. q(mesh))
        table.insert(cmds, "uci commit xiaoqiang")
        table.insert(cmds, "[ -x /etc/init.d/mapd ] && /etc/init.d/mapd restart >/dev/null 2>&1")
        table.insert(cmds, "[ -x /etc/init.d/topomon ] && /etc/init.d/topomon restart >/dev/null 2>&1")
        mesh_changed = true
    end

    if changed then
        table.insert(cmds, "uci commit wireless")
        local reload_any = false
        for d in pairs(reload_devs) do
            reload_any = true
            table.insert(cmds, "wifi reload " .. q(d) .. " >/dev/null 2>&1")
        end
        if not reload_any then
            table.insert(cmds, "wifi reload MT7981_1_1 >/dev/null 2>&1")
            table.insert(cmds, "wifi reload MT7981_1_2 >/dev/null 2>&1")
        end
    end

    local out = ""
    if #cmds > 0 then
        local ok, out2 = run_remote(cmds)
        out = out2 or ""
        if not ok then
            json_error(format_ssh_error(out2))
            return
        end
    end

    if debug then
        local after = {}
        for _, b in ipairs(ifaces) do
            after[b] = ssh_capture("uci -q show wireless." .. b .. "; iwinfo " .. b .. " info 2>/dev/null")
        end
        for d in pairs(devs) do
            after[d] = ssh_capture("uci -q show wireless." .. d)
        end
        http.write(jsonc.stringify({ ok = true, changed = changed or mesh_changed, debug = { cmds = cmds, out = out, after = after } }))
    else
        http.write(jsonc.stringify({ ok = true, changed = changed or mesh_changed }))
    end
end

function wifi_restart()
    http.prepare_content("application/json")
    local ok = ssh_exec("/sbin/wifi restart >/dev/null 2>&1")
    if not ok then
        http.write(jsonc.stringify({ ok = false, error = format_ssh_error(nil) }))
        return
    end
    http.write(jsonc.stringify({ ok = true }))
end

function router_reboot()
    http.prepare_content("application/json")
    local ok = ssh_exec("reboot >/dev/null 2>&1")
    if not ok then
        http.write(jsonc.stringify({ ok = false, error = format_ssh_error(nil) }))
        return
    end
    http.write(jsonc.stringify({ ok = true }))
end

