local ffi = require'ffi'
local string_len = string.len
local sodium_lib

-- https://libsodium.gitbook.io/doc/usage
ffi.cdef[[
int sodium_init(void);
]]

-- https://libsodium.gitbook.io/doc/helpers
ffi.cdef[[
int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);
char *sodium_bin2hex(char * const hex, const size_t hex_maxlen,
                     const unsigned char * const bin, const size_t bin_len);
int sodium_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
                   const char * const hex, const size_t hex_len,
                   const char * const ignore, size_t * const bin_len,
                   const char ** const hex_end);
char *sodium_bin2base64(char * const b64, const size_t b64_maxlen,
                        const unsigned char * const bin, const size_t bin_len,
                        const int variant);
int sodium_base642bin(unsigned char * const bin, const size_t bin_maxlen,
                      const char * const b64, const size_t b64_len,
                      const char * const ignore, size_t * const bin_len,
                      const char ** const b64_end, const int variant);
void sodium_increment(unsigned char *n, const size_t nlen);
void sodium_add(unsigned char *a, const unsigned char *b, const size_t len);
void sodium_sub(unsigned char *a, const unsigned char *b, const size_t len);
int sodium_compare(const void * const b1_, const void * const b2_, size_t len);
int sodium_is_zero(const unsigned char *n, const size_t nlen);
void sodium_stackzero(const size_t len);

size_t sodium_base64_encoded_len(size_t bin_len, int variant);
]]

-- https://libsodium.gitbook.io/doc/padding
ffi.cdef[[
int sodium_pad(size_t *padded_buflen_p, unsigned char *buf,
               size_t unpadded_buflen, size_t blocksize, size_t max_buflen);
int sodium_unpad(size_t *unpadded_buflen_p, const unsigned char *buf,
                 size_t padded_buflen, size_t blocksize);
]]

-- skipping https://libsodium.gitbook.io/doc/memory_management for now

local function test_cspace()
  if ffi.C.randombytes_random then
    return ffi.C
  end
end

do
  local ok, lib = pcall(test_cspace)
  if ok then
    sodium_lib = lib
  else
    sodium_lib = ffi.load('sodium')
  end
end

local function luasodium_init()
  return sodium_lib.sodium_init() ~= -1
end

local function luasodium_memcmp(p1,p2,len)
  return sodium_lib.sodium_memcmp(p1,p2,len) == 0
end

local function luasodium_bin2hex(bin,bin_len)
  local hex_len = bin_len * 2
  local hex = ffi.new('char[?]',hex_len + 1)
  sodium_lib.sodium_bin2hex(hex,hex_len+1,bin,bin_len)
  return ffi.string(hex)
end

local function luasodium_hex2bin(hex,hex_len,ignore)
  local bin_len = hex_len / 2
  if bin_len % 2 ~= 0 then
    bin_len = bin_len + 1
  end
  local tmp_hex = ffi.new('char[?]',hex_len,hex)
  local bin = ffi.new('char[?]',bin_len)
  local out_bin_len = ffi.new('size_t[1]')
  local hex_end = ffi.new('const char *[1]')
  if sodium_lib.sodium_hex2bin(
    bin,bin_len,
    tmp_hex,hex_len,
    ignore,out_bin_len,
    hex_end) ~= 0 then
    return nil,'error in hex2bin'
  end
  local rem
  if hex_end[0] < tmp_hex + hex_len then
    rem = ffi.string(hex_end[0], (tmp_hex + hex_len) - hex_end[0])
  end
  return ffi.string(bin,out_bin_len[0]), rem
end

local function luasodium_bin2base64(bin,bin_len,variant)
  local b64_len = sodium_lib.sodium_base64_encoded_len(bin_len,variant)

  local b64 = ffi.new('char[?]',b64_len)

  sodium_lib.sodium_bin2base64(
    b64, b64_len,
    bin,bin_len,variant)
  return ffi.string(b64)
end

local function luasodium_base642bin(base64,base64_len,variant,ignore)
  local bin_len = base64_len
  local tmp_base64 = ffi.new('char[?]',base64_len,base64)
  local bin = ffi.new('char[?]',bin_len)
  local out_bin_len = ffi.new('size_t[1]')
  local base64_end = ffi.new('const char *[1]')

  if sodium_lib.sodium_base642bin(
    bin,bin_len,
    tmp_base64,base64_len,
    ignore,out_bin_len,
    base64_end,variant) ~= 0 then
    return nil,'error in base642bin'
  end
  local rem
  if base64_end[0] < tmp_base64 + base64_len then
    rem = ffi.string(base64_end[0], (tmp_base64 + base64_len) - base64_end[0])
  end
  return ffi.string(bin,out_bin_len[0]), rem
end

local function luasodium_increment(n)
  local nlen = string_len(n)
  local tmp_n = ffi.new('char[?]',nlen,n)
  sodium_lib.sodium_increment(tmp_n,nlen)
  return ffi.string(tmp_n,nlen)
end

local function luasodium_add(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return nil, 'mismatched datatypes'
  end
  local tmp_a = ffi.new('char[?]',alen,a)

  sodium_lib.sodium_add(tmp_a,b,alen)
  return ffi.string(tmp_a,alen)
end

local function luasodium_sub(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return nil, 'mismatched datatypes'
  end
  local tmp_a = ffi.new('char[?]',alen,a)

  sodium_lib.sodium_sub(tmp_a,b,alen)
  return ffi.string(tmp_a,alen)
end

local function luasodium_compare(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return nil, 'mismatched datatypes'
  end

  return sodium_lib.sodium_compare(a,b,alen)
end

local function luasodium_is_zero(n)
  return sodium_lib.sodium_is_zero(n,string_len(n)) == 1
end

local function luasodium_pad(n,blocksize)
  local nlen = string_len(n)
  local rem = nlen % blocksize
  local rounded = nlen + (blocksize - rem)

  local r = ffi.new('char[?]',rounded,n)
  local outlen = ffi.new('size_t[1]')

  if sodium_lib.sodium_pad(outlen,r,
    nlen,blocksize,rounded) ~= 0 then
    return nil, 'sodium_pad error'
  end

  return ffi.string(r,outlen[0])
end

local function luasodium_unpad(n,blocksize)
  local nlen = string_len(n)
  local outlen = ffi.new('size_t[1]')

  if sodium_lib.sodium_unpad(outlen,n,
    nlen,blocksize) ~= 0 then
    return nil, 'sodium_unpad error'
  end

  return ffi.string(n,outlen[0])
end

local M = {
  init = luasodium_init,
  memcmp = luasodium_memcmp,
  bin2hex = luasodium_bin2hex,
  hex2bin = luasodium_hex2bin,
  bin2base64 = luasodium_bin2base64,
  base642bin = luasodium_base642bin,
  increment = luasodium_increment,
  add = luasodium_add,
  sub = luasodium_sub,
  is_zero = luasodium_is_zero,
  compare = luasodium_compare,
  pad = luasodium_pad,
  unpad = luasodium_unpad,
  base64_VARIANT_ORIGINAL = 1,
  base64_VARIANT_ORIGINAL_NO_PADDING = 3,
  base64_VARIANT_URLSAFE = 5,
  base64_VARIANT_URLSAFE_NO_PADDING = 7,
}

return M
