-- Non-blocking concurrent HTTP transport for KOReader / LuaSocket.
--
-- Motivation: KOReader's normal network calls (socket.http) are blocking, so the
-- book downloader fetches chapters strictly one at a time. This module drives
-- many requests in parallel using non-blocking sockets + socket.select, pumped by
-- UIManager so the UI stays responsive. It is used ONLY by the bulk downloader
-- (via Client:request_async) to parallelize chapter fetches. Login / sync / push
-- keep using the proven blocking Client:request path, so they cannot regress.
--
-- Safety nets:
--  * supported() returns false when LuaSec (required for HTTPS) is missing, so the
--    caller can fall back to the synchronous path.
--  * Every step runs inside xpcall; unexpected errors fail the single request
--    (the downloader treats it like a skipped chapter) instead of hanging.
--  * A per-request deadline caps total time; an expired request is failed.

local socket = require("socket")
local logger = require("logger")
local UIManager = require("ui/uimanager")

local AsyncHttp = {}
AsyncHttp.__index = AsyncHttp

local LOG = "[WeRead][async]"

local ok_ssl, ssl_mod = pcall(require, "ssl")
local HAS_SSL = ok_ssl and ssl_mod ~= nil

local DEFAULT_TOTAL_TIMEOUT = 30  -- seconds per request
local SELECT_TIMEOUT = 0.05       -- seconds to block in socket.select

local active = {}        -- list of in-flight request states
local pump_scheduled = false

local function header_value(headers, name)
    if type(headers) ~= "table" or type(name) ~= "string" then
        return nil
    end
    if headers[name] ~= nil then
        return headers[name]
    end
    local target = name:lower()
    for key, value in pairs(headers) do
        if type(key) == "string" and key:lower() == target then
            return value
        end
    end
    return nil
end

local function is_wait(err)
    return err == "timeout" or err == "wantread" or err == "wantwrite"
end

local function now_sec()
    return socket.gettime()
end

function AsyncHttp.supported()
    return HAS_SSL
end

local function parse_url(url)
    local scheme, host, port, path = url:match("^(https?)://([^:/]+):?(%d*)(/?.*)$")
    if not scheme then
        return nil
    end
    port = (port and port ~= "") and tonumber(port) or (scheme == "https" and 443 or 80)
    if path == "" then
        path = "/"
    end
    return scheme, host, port, path
end

-- Build the raw HTTP request bytes from the already-constructed req_opts.
local function build_request_string(req_opts, body, host, path)
    local method = req_opts.method or (body and "POST" or "GET")
    local req_str = method .. " " .. path .. " HTTP/1.1\r\n"
    req_str = req_str .. "Host: " .. host .. "\r\n"
    for k, v in pairs(req_opts.headers or {}) do
        if type(k) == "string" then
            req_str = req_str .. k .. ": " .. tostring(v) .. "\r\n"
        end
    end
    req_str = req_str .. "Connection: close\r\n\r\n"
    if body then
        req_str = req_str .. body
    end
    return req_str
end

local function parse_response_headers(req)
    local headers = {}
    for _, line in ipairs(req.header_lines) do
        local name, val = line:match("^([^:]+):%s*(.*)$")
        if name then
            headers[name] = val
        end
    end
    req.resp_headers = headers
    local cl = headers["Content-Length"]
    if cl then
        req.content_length = tonumber(cl)
    end
    local te = headers["Transfer-Encoding"]
    if te and tostring(te):lower():find("chunked") then
        req.chunked = true
    end
end

local function complete(req)
    if req.done then
        return
    end
    req.done = true
    if req.is_handle_cookie and req.opts.persist_response_cookies ~= false then
        local sc = header_value(req.resp_headers, "set-cookie")
        if sc then
            pcall(function()
                req.client.settings:merge_set_cookie(sc)
            end)
        end
    end
    pcall(req.on_complete, req.code, req.body, req.resp_headers or {}, req.status_line)
end

local function fail(req, msg)
    if req.done then
        return
    end
    req.done = true
    logger.warn(LOG, "request failed:", tostring(msg), "url=", tostring(req.opts.url))
    pcall(req.on_error, msg)
end

local function step(req)
    local sock = req.sock

    if req.phase == "connect" then
        local c, e = sock:connect(req.host, req.port)
        if c then
            if req.is_https then
                req.phase = "handshake"
                req.need = "write"
            else
                req.phase = "send"
                req.need = "write"
            end
            return
        end
        if e == "wantread" then
            req.need = "read"
            return
        elseif e == "wantwrite" then
            req.need = "write"
            return
        end
        return fail(req, "connect: " .. tostring(e))
    end

    if req.phase == "handshake" then
        local dohandshake = sock.dohandshake
        if type(dohandshake) == "function" then
            local h, e = dohandshake(sock)
            if h then
                req.phase = "send"
                req.need = "write"
                return
            end
            if e == "wantread" then
                req.need = "read"
                return
            elseif e == "wantwrite" then
                req.need = "write"
                return
            end
            return fail(req, "tls handshake: " .. tostring(e))
        end
        -- No explicit dohandshake: assume connect() already completed the handshake.
        req.phase = "send"
        req.need = "write"
        return
    end

    if req.phase == "send" then
        if req.send_pos > #req.send_buf then
            req.phase = "headers"
            req.need = "read"
            return
        end
        local sent, err = sock:send(req.send_buf:sub(req.send_pos))
        if sent and sent > 0 then
            req.send_pos = req.send_pos + sent
            req.need = "write"
            return
        end
        if is_wait(err) then
            req.need = (err == "wantread") and "read" or "write"
            return
        end
        return fail(req, "send: " .. tostring(err))
    end

    if req.phase == "headers" then
        local line, err = sock:receive("*l")
        if line == nil then
            if is_wait(err) then
                req.need = "read"
                return
            end
            if err == "closed" then
                return fail(req, "closed during headers")
            end
            return fail(req, "recv headers: " .. tostring(err))
        end
        if req.status_line == nil then
            req.status_line = line
            local code = line:match("%s(%d%d%d)%s")
            req.code = tonumber(code)
            req.need = "read"
            return
        end
        if line == "" then
            parse_response_headers(req)
            req.phase = "body"
            req.need = "read"
            return
        end
        req.header_lines[#req.header_lines + 1] = line
        req.need = "read"
        return
    end

    if req.phase == "body" then
        if req.chunked then
            if req.chunk_remain == nil then
                local line, err = sock:receive("*l")
                if line == nil then
                    if is_wait(err) then
                        req.need = "read"
                        return
                    end
                    if err == "closed" then
                        return complete(req)
                    end
                    return fail(req, "chunk size: " .. tostring(err))
                end
                local size = tonumber((line:match("^%x+") or "0"), 16)
                if size == 0 then
                    return complete(req)
                end
                req.chunk_remain = size
                req.need = "read"
                return
            end
            local data, err, partial = sock:receive(req.chunk_remain)
            data = data or partial or ""
            if #data > 0 then
                req.body = req.body .. data
                req.chunk_remain = req.chunk_remain - #data
            end
            if req.chunk_remain <= 0 then
                req.chunk_remain = nil
                pcall(function()
                    sock:receive("*l")
                end)
                req.need = "read"
                return
            end
            if is_wait(err) then
                req.need = "read"
                return
            end
            if err == "closed" then
                return complete(req)
            end
            return fail(req, "chunk data: " .. tostring(err))
        elseif req.content_length then
            local remaining = req.content_length - #req.body
            if remaining <= 0 then
                return complete(req)
            end
            local data, err, partial = sock:receive(remaining)
            data = data or partial or ""
            if #data > 0 then
                req.body = req.body .. data
            end
            if #req.body >= req.content_length then
                return complete(req)
            end
            if is_wait(err) then
                req.need = "read"
                return
            end
            if err == "closed" then
                return complete(req)
            end
            return fail(req, "body: " .. tostring(err))
        else
            local data, err, partial = sock:receive(8192)
            data = data or partial or ""
            if #data > 0 then
                req.body = req.body .. data
            end
            if is_wait(err) then
                req.need = "read"
                return
            end
            if err == "closed" then
                return complete(req)
            end
            return fail(req, "body-close: " .. tostring(err))
        end
    end
end

local function pump()
    pump_scheduled = false
    local now = now_sec()
    local alive = {}
    for _, req in ipairs(active) do
        if not req.done then
            if now > req.deadline then
                fail(req, "async total timeout")
            else
                alive[#alive + 1] = req
            end
        end
    end
    active = alive
    if #active == 0 then
        return
    end

    local read_set, write_set = {}, {}
    for _, req in ipairs(active) do
        if req.need == "write" then
            write_set[#write_set + 1] = req.sock
        elseif req.need == "read" then
            read_set[#read_set + 1] = req.sock
        else
            read_set[#read_set + 1] = req.sock
            write_set[#write_set + 1] = req.sock
        end
    end

    local ok, r, w, err = pcall(socket.select, read_set, write_set, SELECT_TIMEOUT)
    if not ok then
        for _, req in ipairs(active) do
            fail(req, "select error: " .. tostring(r))
        end
        return
    end

    local ready = {}
    for _, s in ipairs(r or {}) do
        ready[s] = "read"
    end
    for _, s in ipairs(w or {}) do
        ready[s] = ready[s] or "write"
    end

    for _, req in ipairs(active) do
        if ready[req.sock] then
            local sok, serr = pcall(step, req)
            if not sok then
                fail(req, "step error: " .. tostring(serr))
            end
        end
    end

    if #active > 0 then
        pump_scheduled = true
        UIManager:scheduleIn(0.01, pump)
    end
end

local function ensure_pump()
    if pump_scheduled then
        return
    end
    pump_scheduled = true
    UIManager:scheduleIn(0.01, pump)
end

-- Submit an async request. client provides _build_req_opts + settings (for cookie
-- persistence). on_complete(code, body, headers, status); on_error(message).
function AsyncHttp.submit(client, opts, req_opts, on_complete, on_error)
    local scheme, host, port, path = parse_url(opts.url)
    if not scheme then
        if on_error then
            on_error("async: invalid url")
        end
        return
    end

    local tcp = socket.tcp()
    tcp:settimeout(0)
    local sock
    local is_https = (scheme == "https")
    if is_https then
        if not HAS_SSL then
            if on_error then
                on_error("async: HTTPS unsupported (no LuaSec)")
            end
            return
        end
        local okw, wsock = pcall(ssl_mod.wrap, tcp, {
            mode = "client",
            protocol = "any",
            verify = "none",
            options = "all",
        })
        if not okw or not wsock then
            if on_error then
                on_error("async: ssl wrap failed")
            end
            return
        end
        sock = wsock
    else
        sock = tcp
    end
    sock:settimeout(0)

    local req = {
        client = client,
        opts = opts,
        is_handle_cookie = req_opts._is_handle_cookie,
        sock = sock,
        is_https = is_https,
        host = host,
        port = port,
        send_buf = build_request_string(req_opts, opts.body, host, path),
        send_pos = 1,
        phase = "connect",
        need = "write",
        header_lines = {},
        body = "",
        content_length = nil,
        chunked = false,
        chunk_remain = nil,
        deadline = now_sec() + (opts.timeout_total or DEFAULT_TOTAL_TIMEOUT),
        on_complete = on_complete,
        on_error = on_error,
        done = false,
    }

    active[#active + 1] = req
    ensure_pump()
end

return AsyncHttp
