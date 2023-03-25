
-- 在线DES加密解密、DES在线加密解密
-- http://tool.chacuo.net/cryptdes

-- openssl之EVP系列之5---EVP_Encrypt系列函数详解
-- http://blog.csdn.net/gdwzh/article/details/19230
-- http://blog.csdn.net/gdwzh/article/details/19231

require "resty.evp_h" -- 导入头文件

local ffi       = require "ffi"
local ffi_new   = ffi.new
local ffi_gc    = ffi.gc
local ffi_str   = ffi.string
local ffi_copy  = ffi.copy
local ffi_fill  = ffi.fill

local C = ffi.C

local _M = { _VERSION = '16.04.19' }

-- des加密
function _M.encrypt(key, str, zero_padding)

	if zero_padding then
		return _M.encrypt_zero(key, str)
	else
		return _M.encrypt_pkcs(key, str)
	end

end

-- des加密
function _M.decrypt(key, str, zero_padding)

	if zero_padding then
		return _M.decrypt_zero(key, str)
	else
		return _M.decrypt_pkcs(key, str)
	end

end


function _M.encrypt_pkcs(key, str)

	local str_len = #str
	local buf     = ffi_new("unsigned char[?]", str_len + 8)
	local out_len = ffi_new("int[1]")
	local tmp_len = ffi_new("int[1]")
	local gen_key = ffi_new("unsigned char[?]", 8)
	local des     = C.EVP_des_ecb()

	local  ctx = C.EVP_CIPHER_CTX_new()
	if not ctx then return nil, "no memory" end

	ffi_gc(ctx, C.EVP_CIPHER_CTX_free)
	ffi_copy(gen_key, key, #key)

	if  C.EVP_EncryptInit_ex (ctx, des,  nil,     gen_key, nil) == 0 then return nil end
	if  C.EVP_EncryptUpdate  (ctx, buf,  out_len, str, str_len) == 0 then return nil end
	if  C.EVP_EncryptFinal_ex(ctx, buf + out_len[0],   tmp_len) == 0 then return nil end

	return ffi_str(buf, out_len[0] + tmp_len[0])
end

function _M.decrypt_pkcs(key, str)

	local str_len = #str
	local buf     = ffi_new("unsigned char[?]", str_len)
	local out_len = ffi_new("int[1]")
	local tmp_len = ffi_new("int[1]")
	local gen_key = ffi_new("unsigned char[?]", 8)
	local des     = C.EVP_des_ecb()

	local  ctx = C.EVP_CIPHER_CTX_new()
	if not ctx then return nil, "no memory" end

	ffi_gc(ctx, C.EVP_CIPHER_CTX_free)
	ffi_copy(gen_key, key, #key)

	if  C.EVP_DecryptInit_ex (ctx, des,  nil,     gen_key, nil) == 0 then return nil end
	if  C.EVP_DecryptUpdate  (ctx, buf,  out_len, str, str_len) == 0 then return nil end
	if  C.EVP_DecryptFinal_ex(ctx, buf + out_len[0],   tmp_len) == 0 then return nil end

	return ffi_str(buf, out_len[0] + tmp_len[0])
end


local _floor = math.floor
function _M.encrypt_zero(key, str)

	local str_len = #str
	local tmp_len = _floor(( (str_len-1) / 8 ) + 1) * 8
	local buf     = ffi_new("unsigned char[?]", tmp_len)
	local tem     = ffi.new("unsigned char[?]", tmp_len)
	local out_len = ffi_new("int[1]")
	local gen_key = ffi_new("unsigned char[?]", 8)
	local des     = C.EVP_des_ecb()

	local  ctx = C.EVP_CIPHER_CTX_new()
	if not ctx then return nil, "no memory" end

	ffi_gc(ctx, C.EVP_CIPHER_CTX_free)
	ffi_copy(gen_key, key, #key)

	ffi_fill(tem, tmp_len, 0)
	ffi_copy(tem, str, str_len)

	if  C.EVP_EncryptInit_ex (ctx, des,  nil,     gen_key, nil) == 0 then return nil end
		C.EVP_CIPHER_CTX_set_padding(ctx, 0)
	if  C.EVP_EncryptUpdate  (ctx, buf, out_len,  tem, tmp_len) == 0 then return nil end

	return ffi_str(buf, out_len[0])
end

function _M.decrypt_zero(key, str)

	local str_len = #str
	local buf     = ffi_new("unsigned char[?]", str_len)
	local out_len = ffi_new("int[1]")
	local gen_key = ffi_new("unsigned char[?]", 8)
	local des     = C.EVP_des_ecb()

	local  ctx = C.EVP_CIPHER_CTX_new()
	if not ctx then return nil, "no memory" end

	ffi_gc(ctx, C.EVP_CIPHER_CTX_free)
	ffi_copy(gen_key, key, #key)

	if  C.EVP_DecryptInit_ex (ctx, des,  nil,     gen_key, nil) == 0 then return nil end
		C.EVP_CIPHER_CTX_set_padding(ctx, 0)
	if  C.EVP_DecryptUpdate  (ctx, buf,  out_len, str, str_len) == 0 then return nil end

	local padding_size = 0
		while buf[str_len - padding_size - 1] == 0 do
			padding_size = padding_size + 1
		end
	return ffi_str(buf, out_len[0] - padding_size)
end

return _M
