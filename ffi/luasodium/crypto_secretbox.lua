local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string
local type = type

local char_array = ffi.typeof('char[?]')

local sodium_lib
local constants

local constant_keys = {
  'crypto_secretbox_KEYBYTES',
  'crypto_secretbox_MACBYTES',
  'crypto_secretbox_NONCEBYTES',

  'crypto_secretbox_xsalsa20poly1305_KEYBYTES',
  'crypto_secretbox_xsalsa20poly1305_NONCEBYTES',
  'crypto_secretbox_xsalsa20poly1305_MACBYTES',

  'crypto_secretbox_xchacha20poly1305_KEYBYTES',
  'crypto_secretbox_xchacha20poly1305_NONCEBYTES',
  'crypto_secretbox_xchacha20poly1305_MACBYTES',

  'crypto_secretbox_ZEROBYTES',
  'crypto_secretbox_xsalsa20poly1305_ZEROBYTES',

  'crypto_secretbox_BOXZEROBYTES',
  'crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES',
}

local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],
  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],
  ['crypto_secretbox_keygen'] = [[
    void %s(unsigned char *k)
  ]],
  ['crypto_secretbox'] = [[
      int %s(unsigned char *c,
              const unsigned char *m,
              unsigned long long mlen,
              const unsigned char *n,
              const unsigned char *k)
  ]],
  ['crypto_secretbox_open'] = [[
      int %s(unsigned char *m,
              const unsigned char *c,
              unsigned long long clen,
              const unsigned char *n,
              const unsigned char *k)
  ]],
  ['crypto_secretbox_easy'] = [[
      int %s(unsigned char *c,
              const unsigned char *m,
              unsigned long long mlen,
              const unsigned char *n,
              const unsigned char *k)
  ]],
  ['crypto_secretbox_open_easy'] = [[
      int %s(unsigned char *m,
              const unsigned char *c,
              unsigned long long clen,
              const unsigned char *n,
              const unsigned char *k)
  ]],
  ['crypto_secretbox_detached'] = [[
    int %s(unsigned char *c,
            unsigned char *mac,
            const unsigned char *m,
            unsigned long long mlen,
            const unsigned char *n,
            const unsigned char *k)
  ]],
  ['crypto_secretbox_open_detached'] = [[
    int %s(unsigned char *m,
           const unsigned char *c,
           const unsigned char *mac,
           unsigned long long clen,
           const unsigned char *n,
           const unsigned char *k)
  ]],
}


local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

local c_pointers = { ... }


if #c_pointers == 2 and
  type(c_pointers[1]) == 'table' then
  sodium_lib = {}

  for k,f in pairs(c_pointers[1]) do
    if signatures[k] then
      sodium_lib[k] = ffi.cast(string_format(signatures[k],'(*)'),f)
    end
  end

  constants = c_pointers[2]

else
  ffi.cdef([[
    int sodium_init(void);
  ]])

  do
    local ok, lib = pcall(test_cspace)
    if ok then
      sodium_lib = lib
    else
      sodium_lib = ffi.load('sodium')
    end
  end

  constants = {}
  for _,c in ipairs(constant_keys) do
    ffi.cdef('size_t ' .. c:lower() .. '(void);')
    constants[c] = tonumber(sodium_lib[c:lower()]())
  end

  for f,sig in pairs(signatures) do
    ffi.cdef(string_format(sig,f))
  end
end

-- localize constants
local crypto_secretbox_KEYBYTES     = constants.crypto_secretbox_KEYBYTES
local crypto_secretbox_MACBYTES     = constants.crypto_secretbox_MACBYTES
local crypto_secretbox_NONCEBYTES   = constants.crypto_secretbox_NONCEBYTES
local crypto_secretbox_ZEROBYTES    = constants.crypto_secretbox_ZEROBYTES
local crypto_secretbox_BOXZEROBYTES = constants.crypto_secretbox_BOXZEROBYTES

local function lua_crypto_secretbox(m, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local mlen = string_len(m)
    local clen = mlen + crypto_secretbox_MACBYTES

    if string_len(nonce) ~= crypto_secretbox_NONCEBYTES then
      return error(string_format('wrong nonce size, expected: %d',
        crypto_secretbox_NONCEBYTES))
    end

    if string_len(key) ~= crypto_secretbox_KEYBYTES then
      return error(string_format('wrong key size, expected: %d',
        crypto_secretbox_KEYBYTES))
    end

    local tmp_m = char_array(mlen + crypto_secretbox_ZEROBYTES)
    ffi.fill(tmp_m,crypto_secretbox_ZEROBYTES,0)
    ffi.copy(tmp_m+crypto_secretbox_ZEROBYTES,m,mlen)

    local c = char_array(clen + crypto_secretbox_BOXZEROBYTES)
    ffi.fill(c,crypto_secretbox_BOXZEROBYTES,0)

    if sodium_lib.crypto_secretbox(
      c,tmp_m,mlen+crypto_secretbox_ZEROBYTES,
      nonce,key) == -1  then
      return error('crypto_secretbox error')
    end
    local c_str = ffi_string(c+crypto_secretbox_BOXZEROBYTES,clen)
    sodium_lib.sodium_memzero(tmp_m,mlen + crypto_secretbox_ZEROBYTES)
    sodium_lib.sodium_memzero(c,clen + crypto_secretbox_BOXZEROBYTES)
    return c_str
end

local function lua_crypto_secretbox_open(c, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local clen = string_len(c)

    if clen <= crypto_secretbox_MACBYTES then
      return error(string.format('wrong c size, expected at least: %d',
        crypto_secretbox_MACBYTES))
    end

    if string_len(nonce) ~= crypto_secretbox_NONCEBYTES then
      return error(string_format('wrong nonce size, expected: %d',
        crypto_secretbox_NONCEBYTES))
    end

    if string_len(key) ~= crypto_secretbox_KEYBYTES then
      return error(string_format('wrong key size, expected: %d',
        crypto_secretbox_KEYBYTES))
    end

    local mlen = clen - crypto_secretbox_MACBYTES

    local tmp_c = char_array(clen + crypto_secretbox_BOXZEROBYTES)
    ffi.fill(tmp_c,crypto_secretbox_BOXZEROBYTES,0)
    ffi.copy(tmp_c+crypto_secretbox_BOXZEROBYTES,c,clen)

    local m = char_array(mlen + crypto_secretbox_ZEROBYTES)
    ffi.fill(m,crypto_secretbox_ZEROBYTES,0)

    if sodium_lib.crypto_secretbox_open(
      m,tmp_c,clen+crypto_secretbox_BOXZEROBYTES,
      nonce,key) == -1  then
      return error('crypto_secretbox_open error')
    end

    local m_str = ffi_string(m+crypto_secretbox_ZEROBYTES,mlen)
    sodium_lib.sodium_memzero(tmp_c,clen + crypto_secretbox_BOXZEROBYTES)
    sodium_lib.sodium_memzero(m,mlen + crypto_secretbox_ZEROBYTES)
    return m_str
end

local function lua_crypto_secretbox_easy(m, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local mlen = string_len(m)
    local clen = mlen + crypto_secretbox_MACBYTES

    if string_len(nonce) ~= crypto_secretbox_NONCEBYTES then
      return error(string_format('wrong nonce size, expected: %d',
        crypto_secretbox_NONCEBYTES))
    end

    if string_len(key) ~= crypto_secretbox_KEYBYTES then
      return error(string_format('wrong key size, expected: %d',
        crypto_secretbox_KEYBYTES))
    end

    local c = char_array(clen)

    if sodium_lib.crypto_secretbox_easy(
      c,m,mlen,
      nonce,key) == -1  then
      return error('crypto_secretbox_easy error')
    end

    local c_str = ffi_string(c,clen)
    sodium_lib.sodium_memzero(c,clen)
    return c_str
end

local function lua_crypto_secretbox_open_easy(c, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local clen = string_len(c)

    if clen <= crypto_secretbox_MACBYTES then
      return error(string.format('wrong c size, expected at least: %d',
        crypto_secretbox_MACBYTES))
    end

    if string_len(nonce) ~= crypto_secretbox_NONCEBYTES then
      return error(string_format('wrong nonce size, expected: %d',
        crypto_secretbox_NONCEBYTES))
    end

    if string_len(key) ~= crypto_secretbox_KEYBYTES then
      return error(string_format('wrong key size, expected: %d',
        crypto_secretbox_KEYBYTES))
    end

    local mlen = clen - crypto_secretbox_MACBYTES
    local m = char_array(mlen)

    if sodium_lib.crypto_secretbox_open_easy(
      m,c,clen,
      nonce,key) == -1  then
      return error('crypto_secretbox_open_easy error')
    end

    local m_str = ffi_string(m,mlen)
    sodium_lib.sodium_memzero(m,mlen)
    return m_str
end

local function lua_crypto_secretbox_detached(message, nonce, key)
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
        crypto_secretbox_KEYBYTES))
    end

    local c = char_array(mlen)
    local mac = char_array(crypto_secretbox_MACBYTES)

    if sodium_lib.crypto_secretbox_detached(
      c,mac,message,mlen,
      nonce,key) == -1  then
      return error('crypto_secretbox_detached error')
    end
    local c_str = ffi_string(c,mlen)
    local mac_str = ffi_string(mac,crypto_secretbox_MACBYTES)
    sodium_lib.sodium_memzero(c,mlen)
    sodium_lib.sodium_memzero(mac,crypto_secretbox_MACBYTES)
    return c_str, mac_str
end

local function lua_crypto_secretbox_open_detached(cipher, mac, nonce, key)
  if not key then
    return error('requires 4 arguments')
  end

  local clen = string_len(cipher)

  if string_len(mac) ~= crypto_secretbox_MACBYTES then
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

  local m = char_array(clen)
  if sodium_lib.crypto_secretbox_open_detached(
    m,cipher,mac,clen,
    nonce,key) == -1  then
    return error('crypto_secretbox_open_detached error')
  end

  local m_str = ffi_string(m,clen)
  sodium_lib.sodium_memzero(m,clen)
  return m_str
end

local function lua_crypto_secretbox_keygen()
  local k = char_array(crypto_secretbox_KEYBYTES)
  sodium_lib.crypto_secretbox_keygen(k)
  local k_str = ffi_string(k,crypto_secretbox_KEYBYTES)
  sodium_lib.sodium_memzero(k,crypto_secretbox_KEYBYTES)
  return k_str
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {
  crypto_secretbox = lua_crypto_secretbox,
  crypto_secretbox_open = lua_crypto_secretbox_open,
  crypto_secretbox_easy = lua_crypto_secretbox_easy,
  crypto_secretbox_open_easy = lua_crypto_secretbox_open_easy,
  crypto_secretbox_detached = lua_crypto_secretbox_detached,
  crypto_secretbox_open_detached = lua_crypto_secretbox_open_detached,
  crypto_secretbox_keygen = lua_crypto_secretbox_keygen,
}

for k,v in pairs(constants) do
  M[k] = v
end


return M
