local ffi = require'ffi'

local tonumber = tonumber
local error = error
local string_len = string.len
local string_format = string.format
local math_ceil = math.ceil
local ffi_string = ffi.string
local type= type

local char_array = ffi.typeof('char[?]')

-- no functions for finding these at run-time, just hard-coded
local constants = {
  sodium_base64_VARIANT_ORIGINAL = 1,
  sodium_base64_VARIANT_ORIGINAL_NO_PADDING = 3,
  sodium_base64_VARIANT_URLSAFE = 5,
  sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7,
}

local sodium_lib

local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],

  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],

  ['sodium_memcmp'] = [[
    int %s(const void * const, const void * const, size_t)
  ]],

  ['sodium_bin2hex'] = [[
    char *%s(char * const, const size_t,
             const unsigned char * const, const size_t)
  ]],

  ['sodium_hex2bin'] = [[
    int %s(unsigned char * const, const size_t,
            const char * const, const size_t,
            const char * const, size_t * const,
            const char ** const)
  ]],

  ['sodium_bin2base64'] = [[
    char *%s(char * const, const size_t,
               const unsigned char * const, const size_t,
               const int variant)
  ]],

  ['sodium_base642bin'] = [[
    int %s(unsigned char * const, const size_t,
            const char * const, const size_t,
            const char * const, size_t * const,
            const char ** const, const int)
  ]],

  ['sodium_increment'] = [[
    void %s(unsigned char *, const size_t)
  ]],

  ['sodium_add'] = [[
    void %s(unsigned char *, const unsigned char *, const size_t)
  ]],

  ['sodium_sub'] = [[
    void %s(unsigned char *, const unsigned char *, const size_t)
  ]],

  ['sodium_compare'] = [[
    int %s(const void * const, const void * const, size_t)
  ]],

  ['sodium_is_zero'] = [[
    int %s(const unsigned char *, const size_t)
  ]],

  ['sodium_pad'] = [[
    int %s(size_t *, unsigned char *,
            size_t, size_t, size_t)
  ]],

  ['sodium_unpad'] = [[
    int %s(size_t *, const unsigned char *, size_t, size_t)
  ]],

  ['sodium_base64_encoded_len'] = [[
    size_t %s(size_t bin_len, int variant)
  ]],
}

local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

-- function pointers are passed in from c module
local c_pointers = {...}


if #c_pointers == 2 and
  type(c_pointers[1]) == 'table' then -- we're being loaded from the c module
  sodium_lib = {}

  for k,f in pairs(c_pointers[1]) do
    sodium_lib[k] = ffi.cast(string_format(signatures[k],'(*)'),f)
  end

  for k,v in pairs(c_pointers[2]) do
    constants[k] = v
  end

else
  ffi.cdef[[
    int sodium_init(void);
  ]]

  do
    local ok, lib = pcall(test_cspace)
    if ok then
      sodium_lib = lib
    else
      sodium_lib = ffi.load('sodium')
    end
  end

  for f,sig in pairs(signatures) do
    ffi.cdef(string_format(sig,f))
  end
end

local base64_variants = {
  [constants.sodium_base64_VARIANT_ORIGINAL] = true,
  [constants.sodium_base64_VARIANT_ORIGINAL_NO_PADDING] = true,
  [constants.sodium_base64_VARIANT_URLSAFE] = true,
  [constants.sodium_base64_VARIANT_URLSAFE_NO_PADDING] = true,
}

local function luasodium_init()
  if sodium_lib.sodium_init() == -1 then
    return error('sodium_init error')
  end
  return true
end

local function luasodium_memcmp(p1,p2,len)
  if not len then
    return error('requires 3 arguments')
  end
  return sodium_lib.sodium_memcmp(p1,p2,len) == 0
end

local function luasodium_bin2hex(bin)
  if not bin then
    return error('requires 1 argument')
  end
  local bin_len = string_len(bin)

  local hex_len = bin_len * 2
  local hex = char_array(hex_len + 1)
  sodium_lib.sodium_bin2hex(hex,hex_len+1,bin,bin_len)
  local hex_str = ffi_string(hex)
  sodium_lib.sodium_memzero(hex,hex_len+1)
  return hex_str
end

local function luasodium_hex2bin(hex,ignore)
  if not hex then
    return error('requires 1 argument')
  end
  local hex_len = string_len(hex)

  local bin_len = math_ceil(hex_len / 2)
  local tmp_hex = char_array(hex_len)
  local bin = char_array(bin_len)
  local out_bin_len = ffi.new('size_t[1]')
  local hex_end = ffi.new('const char *[1]')
  local rem

  ffi.copy(tmp_hex,hex,hex_len)

  if sodium_lib.sodium_hex2bin(
    bin,bin_len,
    tmp_hex,hex_len,
    ignore,out_bin_len,
    hex_end) ~= 0 then
    return error('error in hex2bin')
  end

  if hex_end[0] < tmp_hex + hex_len then
    rem = ffi_string(hex_end[0], (tmp_hex + hex_len) - hex_end[0])
  end
  local bin_str = ffi_string(bin,out_bin_len[0])
  sodium_lib.sodium_memzero(tmp_hex,hex_len)
  sodium_lib.sodium_memzero(bin,bin_len)
  return bin_str, rem
end

local function luasodium_bin2base64(bin,variant)
  if not variant then
    return error('requires 2 arguments')
  end

  if not base64_variants[variant] then
    return error('unknown base64 variant')
  end

  local bin_len = string_len(bin)
  local b64_len = tonumber(sodium_lib.sodium_base64_encoded_len(bin_len,variant))

  local b64 = char_array(b64_len)

  sodium_lib.sodium_bin2base64(
    b64, b64_len,
    bin,bin_len,variant)

  local b64_str = ffi_string(b64,b64_len-1)
  sodium_lib.sodium_memzero(b64,b64_len)
  return b64_str
end

local function luasodium_base642bin(base64,variant,ignore)
  if not variant then
    return error('requires 2 arguments')
  end

  if not base64_variants[variant] then
    return error('unknown base64 variant')
  end

  local base64_len = string_len(base64)

  local bin_len = base64_len
  local tmp_base64 = char_array(base64_len)
  local bin = char_array(bin_len)
  local out_bin_len = ffi.new('size_t[1]')
  local base64_end = ffi.new('const char *[1]')
  local rem

  ffi.copy(tmp_base64,base64,base64_len);

  if sodium_lib.sodium_base642bin(
    bin,bin_len,
    tmp_base64,base64_len,
    ignore,out_bin_len,
    base64_end,variant) ~= 0 then
    return error('error in base642bin')
  end

  if base64_end[0] < tmp_base64 + base64_len then
    rem = ffi_string(base64_end[0], (tmp_base64 + base64_len) - base64_end[0])
  end
  local bin_str = ffi_string(bin,out_bin_len[0])

  sodium_lib.sodium_memzero(tmp_base64,base64_len)
  sodium_lib.sodium_memzero(bin,bin_len)

  return bin_str, rem
end

local function luasodium_increment(n)
  local nlen = string_len(n)
  local tmp_n = char_array(nlen)
  ffi.copy(tmp_n,n,nlen)
  sodium_lib.sodium_increment(tmp_n,nlen)
  local ret = ffi_string(tmp_n,nlen)
  sodium_lib.sodium_memzero(tmp_n,nlen)
  return ret
end

local function luasodium_add(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return error('mismatched data sizes')
  end
  local tmp_a = char_array(alen)
  ffi.copy(tmp_a,a,alen)

  sodium_lib.sodium_add(tmp_a,b,alen)
  local ret = ffi_string(tmp_a,alen)
  sodium_lib.sodium_memzero(tmp_a,alen)
  return ret
end

local function luasodium_sub(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return error('mismatched data sizes')
  end
  local tmp_a = char_array(alen)
  ffi.copy(tmp_a,a,alen)

  sodium_lib.sodium_sub(tmp_a,b,alen)
  local ret = ffi_string(tmp_a,alen)
  sodium_lib.sodium_memzero(tmp_a,alen)
  return ret
end

local function luasodium_compare(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return error('mismatched data sizes')
  end

  return sodium_lib.sodium_compare(a,b,alen)
end

local function luasodium_is_zero(n)
  if not n then
    return error('requires 1 argument')
  end
  return sodium_lib.sodium_is_zero(n,string_len(n)) == 1
end

local function luasodium_pad(n,blocksize)
  if not blocksize then
    return error('requires 2 arguments')
  end
  local nlen = string_len(n)
  local rem = nlen % blocksize
  local rounded = nlen + (blocksize - rem)

  local r = char_array(rounded)
  local outlen = ffi.new('size_t[1]')

  ffi.copy(r,n,nlen)

  if sodium_lib.sodium_pad(outlen,r,
    nlen,blocksize,rounded) ~= 0 then
    return error('sodium_pad error')
  end

  local r_str = ffi_string(r,outlen[0])
  sodium_lib.sodium_memzero(r,rounded);
  return r_str
end

local function luasodium_unpad(n,blocksize)
  local nlen = string_len(n)
  local outlen = ffi.new('size_t[1]')

  if sodium_lib.sodium_unpad(outlen,n,
    nlen,blocksize) ~= 0 then
    return error('sodium_unpad error')
  end

  return ffi_string(n,outlen[0])
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {
  sodium_init = luasodium_init,
  sodium_memcmp = luasodium_memcmp,
  sodium_bin2hex = luasodium_bin2hex,
  sodium_hex2bin = luasodium_hex2bin,
  sodium_bin2base64 = luasodium_bin2base64,
  sodium_base642bin = luasodium_base642bin,
  sodium_increment = luasodium_increment,
  sodium_add = luasodium_add,
  sodium_sub = luasodium_sub,
  sodium_is_zero = luasodium_is_zero,
  sodium_compare = luasodium_compare,
  sodium_pad = luasodium_pad,
  sodium_unpad = luasodium_unpad,
}

for k,v in pairs(constants) do
  M[k] = v
end

return M
