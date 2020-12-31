local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string
local type = type

local char_array = ffi.typeof('char[?]')

local constants
local sodium_lib

local constant_keys = {
  'crypto_box_PUBLICKEYBYTES',
  'crypto_box_SECRETKEYBYTES',
  'crypto_box_MACBYTES',
  'crypto_box_NONCEBYTES',
  'crypto_box_SEEDBYTES',
  'crypto_box_BEFORENMBYTES',
  'crypto_box_BOXZEROBYTES',
  'crypto_box_ZEROBYTES',

  'crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES',
  'crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES',
  'crypto_box_curve25519xsalsa20poly1305_MACBYTES',
  'crypto_box_curve25519xsalsa20poly1305_NONCEBYTES',
  'crypto_box_curve25519xsalsa20poly1305_SEEDBYTES',
  'crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES',
  'crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES',
  'crypto_box_curve25519xsalsa20poly1305_ZEROBYTES',

  'crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES',
  'crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES',
  'crypto_box_curve25519xchacha20poly1305_MACBYTES',
  'crypto_box_curve25519xchacha20poly1305_NONCEBYTES',
  'crypto_box_curve25519xchacha20poly1305_SEEDBYTES',
  'crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES',
}

local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],
  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],
  ['crypto_box_keypair'] = [[
    int %s(unsigned char *pk, unsigned char *sk)
  ]],
  ['crypto_box_seed_keypair'] = [[
    int %s(unsigned char *pk, unsigned char *sk,
           const unsigned char *seed)
  ]],
  ['crypto_box'] = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_box_open'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_box_easy'] = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_box_open_easy'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_box_detached'] = [[
      int %s(unsigned char *c, unsigned char *mac,
             const unsigned char *m,
             unsigned long long mlen,
             const unsigned char *n,
             const unsigned char *pk,
             const unsigned char *sk)
  ]],
  ['crypto_box_open_detached'] = [[
      int %s(unsigned char *m,
             const unsigned char *c,
             const unsigned char *mac,
             unsigned long long clen,
             const unsigned char *n,
             const unsigned char *pk,
             const unsigned char *sk)
  ]],
  ['crypto_box_beforenm'] = [[
      int %s(unsigned char *k, const unsigned char *pk,
             const unsigned char *sk)
  ]],
  ['crypto_box_easy_afternm'] = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *k)
  ]],
  ['crypto_box_open_easy_afternm'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *k)
  ]],
  ['crypto_box_detached_afternm'] = [[
      int %s(unsigned char *c, unsigned char *mac,
             const unsigned char *m, unsigned long long mlen,
             const unsigned char *n, const unsigned char *k)
  ]],
  ['crypto_box_open_detached_afternm'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             const unsigned char *mac,
             unsigned long long clen, const unsigned char *n,
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

local crypto_box_PUBLICKEYBYTES = constants.crypto_box_PUBLICKEYBYTES
local crypto_box_SECRETKEYBYTES = constants.crypto_box_SECRETKEYBYTES
local crypto_box_MACBYTES       = constants.crypto_box_MACBYTES
local crypto_box_NONCEBYTES     = constants.crypto_box_NONCEBYTES
local crypto_box_SEEDBYTES      = constants.crypto_box_SEEDBYTES
local crypto_box_BEFORENMBYTES  = constants.crypto_box_BEFORENMBYTES
local crypto_box_BOXZEROBYTES   = constants.crypto_box_BOXZEROBYTES
local crypto_box_ZEROBYTES      = constants.crypto_box_ZEROBYTES

local function lua_crypto_box(m, nonce, pk, sk)
    if not sk then
      return error('requires 4 arguments')
    end

    local mlen = string_len(m)
    local clen = mlen + crypto_box_MACBYTES

    if string_len(nonce) ~= crypto_box_NONCEBYTES then
      return error(string_format('wrong nonce size, expected: %d',
        crypto_box_NONCEBYTES))
    end

    if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
      return error(string_format('wrong key size, expected: %d',
        crypto_box_PUBLICKEYBYTES))
    end

    if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
      return error(string_format('wrong key size, expected: %d',
        crypto_box_PUBLICKEYBYTES))
    end

    local tmp_m = char_array(mlen + crypto_box_ZEROBYTES)
    ffi.fill(tmp_m,crypto_box_ZEROBYTES,0)
    ffi.copy(tmp_m+crypto_box_ZEROBYTES,m,mlen)

    local c = char_array(clen + crypto_box_BOXZEROBYTES)
    ffi.fill(c,crypto_box_BOXZEROBYTES,0)

    if sodium_lib.crypto_box(
      c,tmp_m,mlen+crypto_box_ZEROBYTES,
      nonce,pk,sk) == -1  then
      return error('crypto_box error')
    end
    local c_str = ffi_string(c + crypto_box_BOXZEROBYTES,clen)
    sodium_lib.sodium_memzero(tmp_m,mlen + crypto_box_ZEROBYTES)
    sodium_lib.sodium_memzero(c,clen + crypto_box_BOXZEROBYTES)
    return c_str
end

local function lua_crypto_box_open(c, nonce, pk, sk)
    if not sk then
      return error('requires 4 arguments')
    end

    local clen = string_len(c)

    if clen <= crypto_box_MACBYTES then
      return error(string.format('wrong c size, expected at least: %d',
        crypto_box_MACBYTES))
    end

    if string_len(nonce) ~= crypto_box_NONCEBYTES then
      return error(string_format('wrong nonce size, expected: %d',
        crypto_box_NONCEBYTES))
    end

    if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
      return error(string_format('wrong key size, expected: %d',
        crypto_box_PUBLICKEYBYTES))
    end

    if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
      return error(string_format('wrong key size, expected: %d',
        crypto_box_PUBLICKEYBYTES))
    end

    local mlen = clen - crypto_box_MACBYTES

    local tmp_c = char_array(clen + crypto_box_BOXZEROBYTES)
    ffi.fill(tmp_c,crypto_box_BOXZEROBYTES,0)
    ffi.copy(tmp_c+crypto_box_BOXZEROBYTES,c,clen)

    local m = char_array(mlen + crypto_box_ZEROBYTES)
    ffi.fill(m,crypto_box_ZEROBYTES,0)

    if sodium_lib.crypto_box_open(
      m,tmp_c,clen+crypto_box_BOXZEROBYTES,
      nonce,pk,sk) == -1  then
      return error('crypto_box_open error')
    end

    local m_str = ffi_string(m+crypto_box_ZEROBYTES,mlen)
    sodium_lib.sodium_memzero(tmp_c,clen + crypto_box_BOXZEROBYTES)
    sodium_lib.sodium_memzero(m,mlen + crypto_box_ZEROBYTES)
    return m_str
end

local function lua_crypto_box_easy(m,n,pk,sk)
  local c
  if not sk then
    return error('requires 4 arguments')
  end

  local mlen = string_len(m)
  local clen = mlen + crypto_box_MACBYTES

  if string_len(n) ~= crypto_box_NONCEBYTES then
    return error(string_format(
      'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
  end

  if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
    return error(string_format(
      'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
  end

  if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
    return error(string_format(
      'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
  end

  c = char_array(clen)

  if tonumber(sodium_lib.crypto_box_easy(c,m,mlen,n,pk,sk)) == -1 then
    return error('crypto_box_easy error')
  end

  local c_str = ffi_string(c,clen)
  sodium_lib.sodium_memzero(c,clen)
  return c_str
end

local function lua_crypto_box_open_easy(c,n,pk,sk)
  local m
  if not sk then
    return error('requires 4 arguments')
  end

  local clen = string_len(c)

  if clen <= crypto_box_MACBYTES then
    return error(string_format(
      'wrong cipher length, expected at least: %d',
      crypto_box_MACBYTES))
  end

  if string_len(n) ~= crypto_box_NONCEBYTES then
    return error(string_format(
      'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
  end

  if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
    return error(string_format(
      'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
  end

  if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
    return error(string_format(
      'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
  end

  local mlen = clen - crypto_box_MACBYTES

  m = char_array(mlen)

  if tonumber(sodium_lib.crypto_box_open_easy(m,c,clen,n,pk,sk)) == -1 then
    return error('crypto_box_open_easy error')
  end

  local m_str = ffi_string(m,mlen)
  sodium_lib.sodium_memzero(m,mlen)
  return m_str
end

local function lua_crypto_box_detached(m,n,pk,sk)
  local c
  local mac

  if not sk then
    return error('requires 4 arguments')
  end

  local mlen = string_len(m)

  if string_len(n) ~= crypto_box_NONCEBYTES then
    return error(string_format(
      'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
  end

  if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
    return error(string_format(
      'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
  end

  if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
    return error(string_format(
      'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
  end

  c = char_array(mlen)
  mac = char_array(crypto_box_MACBYTES)

  if tonumber(sodium_lib.crypto_box_detached(c,mac,m,mlen,n,pk,sk)) == -1 then
    return error('crypto_box_detached error')
  end

  local c_str = ffi_string(c,mlen)
  local mac_str = ffi_string(mac,crypto_box_MACBYTES)

  sodium_lib.sodium_memzero(c,mlen)
  sodium_lib.sodium_memzero(mac,crypto_box_MACBYTES)

  return c_str, mac_str
end

local function lua_crypto_box_open_detached(c,mac,n,pk,sk)
  local m

  if not sk then
    return error('requires 5 arguments')
  end

  local clen = string_len(c)
  local maclen = string_len(mac)

  if maclen ~= crypto_box_MACBYTES then
    return error(string_format(
      'wrong mac length, expected: %d',
      crypto_box_MACBYTES))
  end

  if string_len(n) ~= crypto_box_NONCEBYTES then
    return error(string_format(
      'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
  end

  if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
    return error(string_format(
      'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
  end

  if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
    return error(string_format(
      'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
  end

  m = char_array(clen)

  if tonumber(sodium_lib.crypto_box_open_detached(m,c,mac,clen,n,pk,sk)) == -1 then
    return error('crypto_box_open_detached error')
  end

  local m_str = ffi_string(m,clen)
  sodium_lib.sodium_memzero(m,clen)
  return m_str
end

local function lua_crypto_box_beforenm(pk,sk)
  local k

  if not sk then
    return error('requires 2 arguments')
  end

  if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
    return error(string_format(
      'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
  end

  if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
    return error(string_format(
      'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
  end

  k = char_array(crypto_box_BEFORENMBYTES)

  if tonumber(sodium_lib.crypto_box_beforenm(k,pk,sk)) == -1  then
    return error('crypto_box_beforenm error')
  end

  local k_str = ffi_string(k,crypto_box_BEFORENMBYTES)
  sodium_lib.sodium_memzero(k,crypto_box_BEFORENMBYTES)
  return k_str
end

local function lua_crypto_box_easy_afternm(m,n,k)
  local c

  if not k then
    return error('requires 3 arguments')
  end

  local mlen = string_len(m)
  local clen = mlen + crypto_box_MACBYTES

  if string_len(n) ~= crypto_box_NONCEBYTES then
    return error(string_format(
      'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
  end

  if string_len(k) ~= crypto_box_BEFORENMBYTES then
    return error(string_format(
      'wrong shared key length, expected: %d', crypto_box_BEFORENMBYTES))
  end

  c = char_array(clen)

  if tonumber(sodium_lib.crypto_box_easy_afternm(c,m,mlen,n,k)) == -1 then
    return error('crypto_box_easy_afternm')
  end
  local c_str = ffi_string(c,clen)
  sodium_lib.sodium_memzero(c,clen)
  return c_str
end

local function lua_crypto_box_open_easy_afternm(c,n,k)
  local m

  if not k then
    return error('requires 3 arguments')
  end

  local clen = string_len(c)

  if clen <= crypto_box_MACBYTES then
    return error(string_format(
      'wrong cipher length, expected at least: %d',
      crypto_box_MACBYTES))
  end

  if string_len(n) ~= crypto_box_NONCEBYTES then
    return error(string_format(
      'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
  end

  if string_len(k) ~= crypto_box_BEFORENMBYTES then
    return error(string_format(
      'wrong shared key length, expected: %d', crypto_box_BEFORENMBYTES))
  end

  local mlen = clen - crypto_box_MACBYTES

  m = char_array(mlen)

  if tonumber(sodium_lib.crypto_box_open_easy_afternm(m,c,clen,n,k)) == -1 then
    return error('crypto_box_open_easy_afternm')
  end

  local m_str = ffi_string(m,mlen)
  sodium_lib.sodium_memzero(m,mlen)
  return m_str
end

local function lua_crypto_box_detached_afternm(m,n,k)
  local c
  local mac

  if not k then
    return error('requires 3 arguments')
  end

  local mlen = string_len(m)

  if string_len(n) ~= crypto_box_NONCEBYTES then
    return error(string_format(
      'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
  end

  if string_len(k) ~= crypto_box_BEFORENMBYTES then
    return error(string_format(
      'wrong shared key length, expected: %d', crypto_box_BEFORENMBYTES))
  end

  c = char_array(mlen)
  mac = char_array(crypto_box_MACBYTES)

  if tonumber(sodium_lib.crypto_box_detached_afternm(c,mac,m,mlen,n,k)) == -1 then
    return error('crypto_box_detached_afternm error')
  end

  local c_str = ffi_string(c,mlen)
  local mac_str = ffi_string(mac,crypto_box_MACBYTES)

  sodium_lib.sodium_memzero(c,mlen)
  sodium_lib.sodium_memzero(mac,crypto_box_MACBYTES)

  return c_str, mac_str
end

local function lua_crypto_box_open_detached_afternm(c,mac,n,k)
  local m

  if not k then
    return error('requires 4 arguments')
  end

  local clen = string_len(c)
  local maclen = string_len(mac)

  if maclen ~= crypto_box_MACBYTES then
    return error(string_format(
      'wrong mac length, expected: %d',
      crypto_box_MACBYTES))
  end

  if string_len(n) ~= crypto_box_NONCEBYTES then
    return error(string_format(
      'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
  end

  if string_len(k) ~= crypto_box_BEFORENMBYTES then
    return error(string_format(
      'wrong shared key length, expected: %d', crypto_box_BEFORENMBYTES))
  end

  m = char_array(clen)

  if tonumber(sodium_lib.crypto_box_open_detached_afternm(m,c,mac,clen,n,k)) == -1 then
    return error('crypto_box_open_detached_afternm error')
  end
  local m_str = ffi_string(m,clen)
  sodium_lib.sodium_memzero(m,clen)
  return m_str
end

local function lua_crypto_box_keypair()
  local pk = char_array(crypto_box_PUBLICKEYBYTES)
  local sk = char_array(crypto_box_SECRETKEYBYTES)
  if tonumber(sodium_lib.crypto_box_keypair(pk,sk)) == -1 then
    return error('crypto_box_keypair error')
  end

  local pk_str = ffi_string(pk,crypto_box_PUBLICKEYBYTES)
  local sk_str = ffi_string(sk,crypto_box_SECRETKEYBYTES)

  sodium_lib.sodium_memzero(pk,crypto_box_PUBLICKEYBYTES)
  sodium_lib.sodium_memzero(sk,crypto_box_SECRETKEYBYTES)
  return pk_str, sk_str
end

local function lua_crypto_box_seed_keypair(seed)
  if not seed then
    return error('requires 1 argument')
  end
  if string_len(seed) ~= crypto_box_SEEDBYTES then
    return error(string_format(
      'wrong seed length, expected: %d', crypto_box_SEEDBYTES))
  end
  local pk = char_array(crypto_box_PUBLICKEYBYTES)
  local sk = char_array(crypto_box_SECRETKEYBYTES)
  if tonumber(sodium_lib.crypto_box_seed_keypair(pk,sk,seed)) == -1 then
    return error('crypto_box_seed_keypair error')
  end

  local pk_str = ffi_string(pk,crypto_box_PUBLICKEYBYTES)
  local sk_str = ffi_string(sk,crypto_box_SECRETKEYBYTES)
  sodium_lib.sodium_memzero(pk,crypto_box_PUBLICKEYBYTES)
  sodium_lib.sodium_memzero(sk,crypto_box_SECRETKEYBYTES)
  return pk_str, sk_str
end


if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {
  crypto_box = lua_crypto_box,
  crypto_box_open = lua_crypto_box_open,
  crypto_box_easy = lua_crypto_box_easy,
  crypto_box_open_easy = lua_crypto_box_open_easy,
  crypto_box_detached = lua_crypto_box_detached,
  crypto_box_open_detached = lua_crypto_box_open_detached,
  crypto_box_beforenm = lua_crypto_box_beforenm,
  crypto_box_easy_afternm = lua_crypto_box_easy_afternm,
  crypto_box_open_easy_afternm = lua_crypto_box_open_easy_afternm,
  crypto_box_detached_afternm = lua_crypto_box_detached_afternm,
  crypto_box_open_detached_afternm = lua_crypto_box_open_detached_afternm,
  crypto_box_keypair = lua_crypto_box_keypair,
  crypto_box_seed_keypair = lua_crypto_box_seed_keypair,
}

for k,v in pairs(constants) do
  M[k] = v
end

return M

