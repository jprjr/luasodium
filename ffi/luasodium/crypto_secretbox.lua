local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string

local char_array = ffi.typeof('char[?]')

local sodium_lib
local crypto_secretbox_KEYBYTES
local crypto_secretbox_MACBYTES
local crypto_secretbox_NONCEBYTES

local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

local c_pointers = { ... }


if #c_pointers > 1 then
  sodium_lib = {}

  sodium_lib.sodium_init = ffi.cast([[
    int (*)(void)
  ]],c_pointers[1])

  crypto_secretbox_KEYBYTES = c_pointers[2]
  crypto_secretbox_MACBYTES = c_pointers[3]
  crypto_secretbox_NONCEBYTES = c_pointers[4]

  sodium_lib.crypto_secretbox_easy = ffi.cast([[
  int (*)(unsigned char *, const unsigned char *,
          unsigned long long, const unsigned char *,
          const unsigned char *)
  ]],c_pointers[5])

  sodium_lib.crypto_secretbox_open_easy = ffi.cast([[
  int (*)(unsigned char *, const unsigned char *,
          unsigned long long clen, const unsigned char *,
          const unsigned char *)
  ]],c_pointers[6])

  sodium_lib.crypto_secretbox_detached = ffi.cast([[
  int (*)(unsigned char *,
          unsigned char *,
          const unsigned char *,
          unsigned long long,
          const unsigned char *,
          const unsigned char *)
  ]],c_pointers[7])

  sodium_lib.crypto_secretbox_open_detached = ffi.cast([[
  int (*)(unsigned char *,
          const unsigned char *,
          const unsigned char *,
          unsigned long long,
          const unsigned char *,
          const unsigned char *)
  ]],c_pointers[8])

  sodium_lib.crypto_secretbox_keygen = ffi.cast([[
  void (*)(unsigned char[]] .. crypto_secretbox_KEYBYTES .. [[])
  ]],c_pointers[9])
else
  ffi.cdef([[
    int sodium_init(void);
    size_t crypto_secretbox_keybytes(void);
    size_t crypto_secretbox_noncebytes(void);
    size_t crypto_secretbox_macbytes(void);
  ]])
  do
    local ok, lib = pcall(test_cspace)
    if ok then
      sodium_lib = lib
    else
      sodium_lib = ffi.load('sodium')
    end
  end

  crypto_secretbox_KEYBYTES   = tonumber(sodium_lib.crypto_secretbox_keybytes())
  crypto_secretbox_MACBYTES   = tonumber(sodium_lib.crypto_secretbox_macbytes())
  crypto_secretbox_NONCEBYTES = tonumber(sodium_lib.crypto_secretbox_noncebytes())

  ffi.cdef([[
    int crypto_secretbox_easy(unsigned char *c, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *n,
                            const unsigned char *k);
    int crypto_secretbox_open_easy(unsigned char *m, const unsigned char *c,
                                 unsigned long long clen, const unsigned char *n,
                                 const unsigned char *k);
    int crypto_secretbox_detached(unsigned char *c, unsigned char *mac,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *n,
                                const unsigned char *k);
    int crypto_secretbox_open_detached(unsigned char *m,
                                     const unsigned char *c,
                                     const unsigned char *mac,
                                     unsigned long long clen,
                                     const unsigned char *n,
                                     const unsigned char *k);
    void crypto_secretbox_keygen(unsigned char k[]] .. crypto_secretbox_KEYBYTES .. [[]);
]])
end

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
  if sodium_lib.crypto_secretbox_easy(
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
  if sodium_lib.crypto_secretbox_open_easy(
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

  if sodium_lib.crypto_secretbox_detached(
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
  if sodium_lib.crypto_secretbox_open_detached(
    m,cipher,mac,clen,
    nonce,key) == -1  then
    return error('crypto_secretbox_open_detached error')
  end
  return ffi_string(m,clen)
end

local function lua_crypto_secretbox_keygen()
  local k = char_array(crypto_secretbox_KEYBYTES)
  sodium_lib.crypto_secretbox_keygen(k)
  return ffi_string(k,crypto_secretbox_KEYBYTES)
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {
  crypto_secretbox_easy = lua_crypto_secretbox_easy,
  crypto_secretbox_open_easy = lua_crypto_secretbox_open_easy,
  crypto_secretbox_detached = lua_crypto_secretbox_detached,
  crypto_secretbox_open_detached = lua_crypto_secretbox_open_detached,
  crypto_secretbox_keygen = lua_crypto_secretbox_keygen,
  crypto_secretbox_KEYBYTES = crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES = crypto_secretbox_NONCEBYTES,
  crypto_secretbox_MACBYTES = crypto_secretbox_MACBYTES,
}

return M
