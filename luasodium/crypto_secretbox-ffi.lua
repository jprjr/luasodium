local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string

local char_array = ffi.typeof('char[?]')

local c_pointers = { ... }

local crypto_secretbox_KEYBYTES = c_pointers[1]
local crypto_secretbox_NONCEBYTES = c_pointers[2]
local crypto_secretbox_MACBYTES = c_pointers[3]

local crypto_secretbox_easy = ffi.cast([[
int (*)(unsigned char *, const unsigned char *,
        unsigned long long, const unsigned char *,
        const unsigned char *)
]],c_pointers[4])

local crypto_secretbox_open_easy = ffi.cast([[
int (*)(unsigned char *, const unsigned char *,
        unsigned long long clen, const unsigned char *,
        const unsigned char *)
]],c_pointers[5])

local crypto_secretbox_detached = ffi.cast([[
int (*)(unsigned char *,
        unsigned char *,
        const unsigned char *,
        unsigned long long,
        const unsigned char *,
        const unsigned char *)
]],c_pointers[6])

local crypto_secretbox_open_detached = ffi.cast([[
int (*)(unsigned char *,
        const unsigned char *,
        const unsigned char *,
        unsigned long long,
        const unsigned char *,
        const unsigned char *)
]],c_pointers[7])

local crypto_secretbox_keygen = ffi.cast([[
void (*)(unsigned char[]] .. crypto_secretbox_KEYBYTES .. [[])
]],c_pointers[8])

local function lua_crypto_secretbox_easy(message,nonce,key)
  if not key then
    return error('requires 3 arguments')
  end

  local clen = string_len(message) + crypto_secretbox_MACBYTES

  if string_len(nonce) ~= crypto_secretbox_NONCEBYTES then
    return error(string_format('wrong nonce size, expected: %d',
      crypto_secretbox_NONCEBYTES))
  end

  if string_len(key) ~= crypto_secretbox_KEYBYTES then
    return error(string_format('wrong key size, expected: %d',
      crypto_secretbox_NONCEBYTES))
  end

  local c = char_array(clen)
  if crypto_secretbox_easy(
    c,message,string_len(message),
    nonce,key) == -1  then
    return error('crypto_secretbox_easy error')
  end
  return ffi_string(c,clen)
end

local function lua_crypto_secretbox_open_easy(cipher,nonce,key)
  if not key then
    return error('requires 3 arguments')
  end

  local clen = string_len(cipher)

  if clen < crypto_secretbox_MACBYTES then
    return error(string_format('wrong cipher size, expected at least: %d',
      crypto_secretbox_MACBYTES))
  end

  if string_len(nonce) ~= crypto_secretbox_NONCEBYTES then
    return error(string_format('wrong nonce size, expected: %d',
      crypto_secretbox_NONCEBYTES))
  end

  if string_len(key) ~= crypto_secretbox_KEYBYTES then
    return error(string_format('wrong key size, expected: %d',
      crypto_secretbox_NONCEBYTES))
  end

  local mlen = clen - crypto_secretbox_MACBYTES
  if mlen == 0 then
    return ''
  end

  local m = char_array(mlen)
  if crypto_secretbox_open_easy(
    m,cipher,clen,
    nonce,key) == -1  then
    return error('crypto_secretbox_open_easy error')
  end
  return ffi_string(m,mlen)
end

local function lua_crypto_secretbox_detached(message,nonce,key)
  if not key then
    return error('requires 3 arguments')
  end

  local mlen = string_len(message)

  if string_len(nonce) ~= crypto_secretbox_NONCEBYTES then
    return error(string_format('wrong nonce size, expected: %d',
      crypto_secretbox_NONCEBYTES))
  end

  if string_len(key) ~= crypto_secretbox_KEYBYTES then
    return error(string_format('wrong key size, expected: %d',
      crypto_secretbox_NONCEBYTES))
  end

  local c = char_array(mlen)
  local mac = char_array(crypto_secretbox_MACBYTES)

  if crypto_secretbox_detached(
    c,mac,message,mlen,
    nonce,key) == -1  then
    return error('crypto_secretbox_easy error')
  end
  return ffi_string(c,mlen), ffi_string(mac,crypto_secretbox_MACBYTES)
end

local function lua_crypto_secretbox_open_detached(cipher,mac,nonce,key)
  if not key then
    return error('requires 4 arguments')
  end

  local clen = string_len(cipher)

  if string_len(mac) < crypto_secretbox_MACBYTES then
    return error(string_format('wrong mac size, expected: %d',
      crypto_secretbox_MACBYTES))
  end

  if string_len(nonce) ~= crypto_secretbox_NONCEBYTES then
    return error(string_format('wrong nonce size, expected: %d',
      crypto_secretbox_NONCEBYTES))
  end

  if string_len(key) ~= crypto_secretbox_KEYBYTES then
    return error(string_format('wrong key size, expected: %d',
      crypto_secretbox_NONCEBYTES))
  end

  if clen == 0 then
    return ''
  end

  local m = char_array(clen)
  if crypto_secretbox_open_detached(
    m,cipher,mac,clen,
    nonce,key) == -1  then
    return error('crypto_secretbox_open_detached error')
  end
  return ffi_string(m,clen)
end

local function lua_crypto_secretbox_keygen()
  local k = char_array(crypto_secretbox_KEYBYTES)
  crypto_secretbox_keygen(k)
  return ffi_string(k,crypto_secretbox_KEYBYTES)
end


local M = {
  easy = lua_crypto_secretbox_easy,
  open_easy = lua_crypto_secretbox_open_easy,
  detached = lua_crypto_secretbox_detached,
  open_detached = lua_crypto_secretbox_open_detached,
  keygen = lua_crypto_secretbox_keygen,
  KEYBYTES = crypto_secretbox_KEYBYTES,
  NONCEBYTES = crypto_secretbox_NONCEBYTES,
  MACBYTES = crypto_secretbox_MACBYTES,
}

return M
