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
  {
    functions = { 'crypto_box_keypair' },
    signature = [[
      int %s(unsigned char *pk, unsigned char *sk);
    ]],
  },
  {
    functions = { 'crypto_box_seed_keypair' },
    signature = [[
      int %s(unsigned char *pk, unsigned char *sk,
             const unsigned char *seed);
    ]],
  },
  {
    functions = { 'crypto_box', 'crypto_box_open',
                  'crypto_box_easy', 'crypto_box_open_easy' },
    signature = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk);
    ]],
  },
  {
    functions = { 'crypto_box_detached' },
    signature = [[
      int %s(unsigned char *c, unsigned char *mac,
             const unsigned char *m,
             unsigned long long mlen,
             const unsigned char *n,
             const unsigned char *pk,
             const unsigned char *sk);
    ]],
  },
  {
    functions = { 'crypto_box_open_detached' },
    signature = [[
      int %s(unsigned char *m,
             const unsigned char *c,
             const unsigned char *mac,
             unsigned long long clen,
             const unsigned char *n,
             const unsigned char *pk,
             const unsigned char *sk);
    ]],
  },
  {
    functions = { 'crypto_box_beforenm' },
    signature = [[
      int %s(unsigned char *k, const unsigned char *pk,
             const unsigned char *sk);
    ]],
  },
  {
    functions = { 'crypto_box_easy_afternm','crypto_box_open_easy_afternm' },
    signature = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *k);
    ]],
  },
  {
    functions = { 'crypto_box_detached_afternm' },
    signature = [[
      int %s(unsigned char *c, unsigned char *mac,
             const unsigned char *m, unsigned long long mlen,
             const unsigned char *n, const unsigned char *k);
    ]],
  },
  {
    functions = { 'crypto_box_open_detached_afternm' },
    signature = [[
      int %s(unsigned char *m, const unsigned char *c,
             const unsigned char *mac,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *k);
    ]],
  },
}

local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

local c_pointers = { ... }

if #c_pointers == 3 and
  type(c_pointers[1]) == 'table' then
  sodium_lib = {}

  sodium_lib.sodium_init = ffi.cast(
    c_pointers[1].sodium_init.signature,
    c_pointers[1].sodium_init.func)

  sodium_lib.sodium_memzero = ffi.cast(
    c_pointers[1].sodium_memzero.signature,
    c_pointers[1].sodium_memzero.func)

  constants = c_pointers[2]

  for _,f in ipairs(c_pointers[3]) do
    sodium_lib[f.name] = ffi.cast(f.signature,f.func)
  end


else
  ffi.cdef([[
    int sodium_init(void);
    void sodium_memzero(void * const pnt, const size_t len);
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

  for _,v in ipairs(signatures) do
    for _,f in ipairs(v.functions) do
      ffi.cdef(string_format(v.signature,f))
    end
  end

end

local function lua_crypto_box_keypair(fname,pksize,sksize)
  return function()
    local pk = char_array(pksize)
    local sk = char_array(sksize)
    if tonumber(sodium_lib[fname](pk,sk)) == -1 then
      return error('crypto_box_keypair error')
    end

    local pk_str = ffi_string(pk,pksize)
    local sk_str = ffi_string(sk,sksize)

    sodium_lib.sodium_memzero(pk,pksize)
    sodium_lib.sodium_memzero(sk,sksize)
    return pk_str, sk_str
  end
end

local function lua_crypto_box_seed_keypair(fname,pksize,sksize,seedsize)
  return function(seed)
    if not seed then
      return error('requires 1 argument')
    end
    if string_len(seed) ~= seedsize then
      return error(string_format(
        'wrong seed length, expected: %d', seedsize))
    end
    local pk = char_array(pksize)
    local sk = char_array(sksize)
    if tonumber(sodium_lib[fname](pk,sk,seed)) == -1 then
      return error(string_format('%s error',fname))
    end

    local pk_str = ffi_string(pk,pksize)
    local sk_str = ffi_string(sk,sksize)
    sodium_lib.sodium_memzero(pk,pksize)
    sodium_lib.sodium_memzero(sk,sksize)
    return pk_str, sk_str
  end
end

local function lua_crypto_box()
  return nil
end

local function lua_crypto_box_open()
  return nil
end

local function lua_crypto_box_easy(fname,noncesize,macsize,pksize,sksize)
  return function(m,n,pk,sk)
    local c
    if not sk then
      return error('requires 4 arguments')
    end

    local mlen = string_len(m)
    local clen = mlen + macsize

    if string_len(n) ~= noncesize then
      return error(string_format(
        'wrong nonce length, expected: %d', noncesize))
    end

    if string_len(pk) ~= pksize then
      return error(string_format(
        'wrong public key length, expected: %d', pksize))
    end

    if string_len(sk) ~= sksize then
      return error(string_format(
        'wrong secret key length, expected: %d', sksize))
    end

    c = char_array(clen)

    if tonumber(sodium_lib[fname](c,m,mlen,n,pk,sk)) == -1 then
      return error(string_format('%s error',fname))
    end

    local c_str = ffi_string(c,clen)
    sodium_lib.sodium_memzero(c,clen)
    return c_str
  end
end

local function lua_crypto_box_open_easy(fname,noncesize,macsize,pksize,sksize)
  return function(c,n,pk,sk)
    local m
    if not sk then
      return error('requires 4 arguments')
    end

    local clen = string_len(c)

    if clen <= macsize then
      return error(string_format(
        'wrong cipher length, expected at least: %d',
        macsize))
    end

    if string_len(n) ~= noncesize then
      return error(string_format(
        'wrong nonce length, expected: %d', noncesize))
    end

    if string_len(pk) ~= pksize then
      return error(string_format(
        'wrong public key length, expected: %d', pksize))
    end

    if string_len(sk) ~= sksize then
      return error(string_format(
        'wrong secret key length, expected: %d', sksize))
    end

    local mlen = clen - macsize

    m = char_array(mlen)

    if tonumber(sodium_lib[fname](m,c,clen,n,pk,sk)) == -1 then
      return error(string_format('%s error',fname))
    end

    local m_str = ffi_string(m,mlen)
    sodium_lib.sodium_memzero(m,mlen)
    return m_str
  end
end

local function lua_crypto_box_detached(fname,noncesize,macsize,pksize,sksize)
  return function(m,n,pk,sk)
    local c
    local mac

    if not sk then
      return error('requires 4 arguments')
    end

    local mlen = string_len(m)

    if string_len(n) ~= noncesize then
      return error(string_format(
        'wrong nonce length, expected: %d', noncesize))
    end

    if string_len(pk) ~= pksize then
      return error(string_format(
        'wrong public key length, expected: %d', pksize))
    end

    if string_len(sk) ~= sksize then
      return error(string_format(
        'wrong secret key length, expected: %d', sksize))
    end

    c = char_array(mlen)
    mac = char_array(macsize)

    if tonumber(sodium_lib[fname](c,mac,m,mlen,n,pk,sk)) == -1 then
      return error(string_format('%s error',fname))
    end

    local c_str = ffi_string(c,mlen)
    local mac_str = ffi_string(mac,macsize)

    sodium_lib.sodium_memzero(c,mlen)
    sodium_lib.sodium_memzero(mac,macsize)

    return c_str, mac_str
  end
end

local function lua_crypto_box_open_detached(fname,noncesize,macsize,pksize,sksize)
  return function(c,mac,n,pk,sk)
    local m

    if not sk then
      return error('requires 5 arguments')
    end

    local clen = string_len(c)
    local maclen = string_len(mac)

    if maclen ~= macsize then
      return error(string_format(
        'wrong mac length, expected: %d',
        macsize))
    end

    if string_len(n) ~= noncesize then
      return error(string_format(
        'wrong nonce length, expected: %d', noncesize))
    end

    if string_len(pk) ~= pksize then
      return error(string_format(
        'wrong public key length, expected: %d', pksize))
    end

    if string_len(sk) ~= sksize then
      return error(string_format(
        'wrong secret key length, expected: %d', sksize))
    end

    m = char_array(clen)

    if tonumber(sodium_lib[fname](m,c,mac,clen,n,pk,sk)) == -1 then
      return error(string_format('%s error',fname))
    end

    local m_str = ffi_string(m,clen)
    sodium_lib.sodium_memzero(m,clen)
    return m_str
  end
end

local function lua_crypto_box_beforenm(fname,ksize,pksize,sksize)
  return function(pk,sk)
    local k

    if not sk then
      return error('requires 2 arguments')
    end

    if string_len(pk) ~= pksize then
      return error(string_format(
        'wrong public key length, expected: %d', pksize))
    end

    if string_len(sk) ~= sksize then
      return error(string_format(
        'wrong secret key length, expected: %d', sksize))
    end

    k = char_array(ksize)

    if tonumber(sodium_lib[fname](k,pk,sk)) == -1  then
      return error(string_format('%s error',fname))
    end

    local k_str = ffi_string(k,ksize)
    sodium_lib.sodium_memzero(k,ksize)
    return k_str
  end
end

local function lua_crypto_box_easy_afternm(fname,noncesize,macsize,ksize)
  return function(m,n,k)
    local c

    if not k then
      return error('requires 3 arguments')
    end

    local mlen = string_len(m)
    local clen = mlen + macsize

    if string_len(n) ~= noncesize then
      return error(string_format(
        'wrong nonce length, expected: %d', noncesize))
    end

    if string_len(k) ~= ksize then
      return error(string_format(
        'wrong shared key length, expected: %d', ksize))
    end

    c = char_array(clen)

    if tonumber(sodium_lib[fname](c,m,mlen,n,k)) == -1 then
      return error(string_format('%s error',fname))
    end
    local c_str = ffi_string(c,clen)
    sodium_lib.sodium_memzero(c,clen)
    return c_str
  end
end

local function lua_crypto_box_open_easy_afternm(fname,noncesize,macsize,ksize)
  return function(c,n,k)
    local m

    if not k then
      return error('requires 3 arguments')
    end

    local clen = string_len(c)

    if clen <= macsize then
      return error(string_format(
        'wrong cipher length, expected at least: %d',
        macsize))
    end

    if string_len(n) ~= noncesize then
      return error(string_format(
        'wrong nonce length, expected: %d', noncesize))
    end

    if string_len(k) ~= ksize then
      return error(string_format(
        'wrong shared key length, expected: %d', ksize))
    end

    local mlen = clen - macsize

    m = char_array(mlen)

    if tonumber(sodium_lib[fname](m,c,clen,n,k)) == -1 then
      return error(string_format('%s error',fname))
    end

    local m_str = ffi_string(m,mlen)
    sodium_lib.sodium_memzero(m,mlen)
    return m_str
  end
end

local function lua_crypto_box_detached_afternm(fname,noncesize,macsize,ksize)
  return function(m,n,k)
    local c
    local mac

    if not k then
      return error('requires 3 arguments')
    end

    local mlen = string_len(m)

    if string_len(n) ~= noncesize then
      return error(string_format(
        'wrong nonce length, expected: %d', noncesize))
    end

    if string_len(k) ~= ksize then
      return error(string_format(
        'wrong shared key length, expected: %d', ksize))
    end

    c = char_array(mlen)
    mac = char_array(macsize)

    if tonumber(sodium_lib[fname](c,mac,m,mlen,n,k)) == -1 then
      return error(string_format('%s error',fname))
    end

    local c_str = ffi_string(c,mlen)
    local mac_str = ffi_string(mac,macsize)

    sodium_lib.sodium_memzero(c,mlen)
    sodium_lib.sodium_memzero(mac,macsize)

    return c_str, mac_str
  end
end

local function lua_crypto_box_open_detached_afternm(fname, noncesize, macsize, ksize)
  return function(c,mac,n,k)
    local m

    if not k then
      return error('requires 4 arguments')
    end

    local clen = string_len(c)
    local maclen = string_len(mac)

    if maclen ~= macsize then
      return error(string_format(
        'wrong mac length, expected: %d',
        macsize))
    end

    if string_len(n) ~= noncesize then
      return error(string_format(
        'wrong nonce length, expected: %d', noncesize))
    end

    if string_len(k) ~= ksize then
      return error(string_format(
        'wrong shared key length, expected: %d', ksize))
    end

    m = char_array(clen)

    if tonumber(sodium_lib[fname](m,c,mac,clen,n,k)) == -1 then
      return error(string_format('%s error',fname))
    end
    local m_str = ffi_string(m,clen)
    sodium_lib.sodium_memzero(m,clen)
    return m_str
  end
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {}

for k,v in pairs(constants) do
  M[k] = v
end

M.crypto_box_keypair = lua_crypto_box_keypair(
  'crypto_box_keypair',
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES)

M.crypto_box_seed_keypair = lua_crypto_box_seed_keypair(
  'crypto_box_seed_keypair',
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES)

M.crypto_box = lua_crypto_box(
  'crypto_box',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES,
  constants.crypto_box_BOXZEROBYTES,
  constants.crypto_box_ZEROBYTES)

M.crypto_box_open = lua_crypto_box_open(
  'crypto_box_open',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES,
  constants.crypto_box_ZEROBYTES,
  constants.crypto_box_BOXZEROBYTES)

M.crypto_box_easy = lua_crypto_box_easy(
  'crypto_box_easy',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES)

M.crypto_box_open_easy = lua_crypto_box_open_easy(
  'crypto_box_open_easy',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES)

M.crypto_box_detached = lua_crypto_box_detached(
  'crypto_box_detached',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES)

M.crypto_box_open_detached = lua_crypto_box_open_detached(
  'crypto_box_open_detached',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES)

M.crypto_box_beforenm = lua_crypto_box_beforenm(
  'crypto_box_beforenm',
  constants.crypto_box_BEFORENMBYTES,
  constants.crypto_box_PUBLICKEYBYTES,
  constants.crypto_box_SECRETKEYBYTES)

M.crypto_box_easy_afternm = lua_crypto_box_easy_afternm(
  'crypto_box_easy_afternm',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_BEFORENMBYTES)

M.crypto_box_open_easy_afternm = lua_crypto_box_open_easy_afternm(
  'crypto_box_open_easy_afternm',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_BEFORENMBYTES)

M.crypto_box_detached_afternm = lua_crypto_box_detached_afternm(
  'crypto_box_detached_afternm',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_BEFORENMBYTES)

M.crypto_box_open_detached_afternm = lua_crypto_box_open_detached_afternm(
  'crypto_box_open_detached_afternm',
  constants.crypto_box_NONCEBYTES,
  constants.crypto_box_MACBYTES,
  constants.crypto_box_BEFORENMBYTES)

return M

