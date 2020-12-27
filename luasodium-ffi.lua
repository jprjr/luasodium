local ffi = require'ffi'

local tonumber = tonumber
local error = error
local string_len = string.len
local math_ceil = math.ceil
local ffi_string = ffi.string

local char_array = ffi.typeof('char[?]')

-- function pointers are passed in from c module
local c_pointers = {...}

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

local sodium_init = ffi.cast([[
int (*)(void)
]],c_pointers[1])

local sodium_memcmp = ffi.cast([[
int (*)(const void * const, const void * const, size_t)
]],c_pointers[2])

local sodium_bin2hex = ffi.cast([[
char *(*)(char * const, const size_t,
          const unsigned char * const, const size_t)
]],c_pointers[3])

local sodium_hex2bin = ffi.cast([[
int (*)(unsigned char * const, const size_t,
        const char * const, const size_t,
        const char * const, size_t * const,
       const char ** const)
]],c_pointers[4])

local sodium_bin2base64 = ffi.cast([[
char * (*)(char * const, const size_t,
           const unsigned char * const, const size_t,
           const int variant)
]],c_pointers[5])

local sodium_base642bin = ffi.cast([[
int (*)(unsigned char * const, const size_t,
        const char * const, const size_t,
        const char * const, size_t * const,
        const char ** const, const int)
]],c_pointers[6])

local sodium_increment = ffi.cast([[
void (*)(unsigned char *, const size_t)
]], c_pointers[7])

local sodium_add = ffi.cast([[
void (*)(unsigned char *, const unsigned char *, const size_t)
]],c_pointers[8])

local sodium_sub = ffi.cast([[
void (*)(unsigned char *, const unsigned char *, const size_t)
]],c_pointers[9])

local sodium_compare = ffi.cast([[
int (*)(const void * const, const void * const, size_t)
]],c_pointers[10])

local sodium_is_zero = ffi.cast([[
int (*)(const unsigned char *, const size_t)
]],c_pointers[11])

local sodium_pad = ffi.cast([[
int (*)(size_t *, unsigned char *,
        size_t, size_t, size_t)
]],c_pointers[12])

local sodium_unpad = ffi.cast([[
int (*)(size_t *, const unsigned char *, size_t, size_t)
]],c_pointers[13])

local sodium_base64_encoded_len = ffi.cast([[
size_t (*)(size_t bin_len, int variant)
]],c_pointers[14])

local sodium_base64_VARIANT_ORIGINAL = c_pointers[15]
local sodium_base64_VARIANT_ORIGINAL_NO_PADDING = c_pointers[16]
local sodium_base64_VARIANT_URLSAFE = c_pointers[17]
local sodium_base64_VARIANT_URLSAFE_NO_PADDING = c_pointers[18]

local base64_variants = {
  [sodium_base64_VARIANT_ORIGINAL] = true,
  [sodium_base64_VARIANT_ORIGINAL_NO_PADDING] = true,
  [sodium_base64_VARIANT_URLSAFE] = true,
  [sodium_base64_VARIANT_URLSAFE_NO_PADDING] = true,
}

local function luasodium_init()
  if sodium_init() == -1 then
    return error('sodium_init error')
  end
  return true
end

local function luasodium_memcmp(p1,p2,len)
  if not len then
    return error('requires 3 arguments')
  end
  return sodium_memcmp(p1,p2,len) == 0
end

local function luasodium_bin2hex(bin)
  if not bin then
    return error('requires 1 argument')
  end
  local bin_len = string_len(bin)

  local hex_len = bin_len * 2
  local hex = char_array(hex_len + 1)
  sodium_bin2hex(hex,hex_len+1,bin,bin_len)
  return ffi_string(hex)
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

  if sodium_hex2bin(
    bin,bin_len,
    tmp_hex,hex_len,
    ignore,out_bin_len,
    hex_end) ~= 0 then
    return error('error in hex2bin')
  end

  if hex_end[0] < tmp_hex + hex_len then
    rem = ffi_string(hex_end[0], (tmp_hex + hex_len) - hex_end[0])
  end
  return ffi_string(bin,out_bin_len[0]), rem
end

local function luasodium_bin2base64(bin,variant)
  if not variant then
    return error('requires 2 arguments')
  end

  if not base64_variants[variant] then
    return error('unknown base64 variant')
  end

  local bin_len = string_len(bin)
  local b64_len = tonumber(sodium_base64_encoded_len(bin_len,variant))

  local b64 = char_array(b64_len)

  sodium_bin2base64(
    b64, b64_len,
    bin,bin_len,variant)

  return ffi_string(b64,b64_len-1)
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

  if sodium_base642bin(
    bin,bin_len,
    tmp_base64,base64_len,
    ignore,out_bin_len,
    base64_end,variant) ~= 0 then
    return error('error in base642bin')
  end

  if base64_end[0] < tmp_base64 + base64_len then
    rem = ffi_string(base64_end[0], (tmp_base64 + base64_len) - base64_end[0])
  end

  return ffi_string(bin,out_bin_len[0]), rem
end

local function luasodium_increment(n)
  local nlen = string_len(n)
  local tmp_n = char_array(nlen)
  ffi.copy(tmp_n,n,nlen)
  sodium_increment(tmp_n,nlen)
  return ffi_string(tmp_n,nlen)
end

local function luasodium_add(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return error('mismatched data sizes')
  end
  local tmp_a = char_array(alen)
  ffi.copy(tmp_a,a,alen)

  sodium_add(tmp_a,b,alen)
  return ffi_string(tmp_a,alen)
end

local function luasodium_sub(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return error('mismatched data sizes')
  end
  local tmp_a = char_array(alen)
  ffi.copy(tmp_a,a,alen)

  sodium_sub(tmp_a,b,alen)
  return ffi_string(tmp_a,alen)
end

local function luasodium_compare(a,b)
  local alen = string_len(a)
  local blen = string_len(b)
  if alen ~= blen then
    return error('mismatched data sizes')
  end

  return sodium_compare(a,b,alen)
end

local function luasodium_is_zero(n)
  if not n then
    return error('requires 1 argument')
  end
  return sodium_is_zero(n,string_len(n)) == 1
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

  if sodium_pad(outlen,r,
    nlen,blocksize,rounded) ~= 0 then
    return error('sodium_pad error')
  end

  return ffi_string(r,outlen[0])
end

local function luasodium_unpad(n,blocksize)
  local nlen = string_len(n)
  local outlen = ffi.new('size_t[1]')

  if sodium_unpad(outlen,n,
    nlen,blocksize) ~= 0 then
    return error('sodium_unpad error')
  end

  return ffi_string(n,outlen[0])
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
  base64_VARIANT_ORIGINAL = sodium_base64_VARIANT_ORIGINAL,
  base64_VARIANT_ORIGINAL_NO_PADDING = sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
  base64_VARIANT_URLSAFE = sodium_base64_VARIANT_URLSAFE,
  base64_VARIANT_URLSAFE_NO_PADDING = sodium_base64_VARIANT_URLSAFE_NO_PADDING,
}

return M
