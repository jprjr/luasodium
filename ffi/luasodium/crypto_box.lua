local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string

local char_array = ffi.typeof('char[?]')

local sodium_lib
local crypto_box_PUBLICKEYBYTES
local crypto_box_SECRETKEYBYTES
local crypto_box_MACBYTES
local crypto_box_NONCEBYTES
local crypto_box_SEEDBYTES
local crypto_box_BEFORENMBYTES

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

  crypto_box_PUBLICKEYBYTES = c_pointers[2]
  crypto_box_SECRETKEYBYTES = c_pointers[3]
  crypto_box_MACBYTES       = c_pointers[4]
  crypto_box_NONCEBYTES     = c_pointers[5]
  crypto_box_SEEDBYTES      = c_pointers[6]
  crypto_box_BEFORENMBYTES  = c_pointers[7]

  sodium_lib.crypto_box_keypair = ffi.cast([[
    int (*)(unsigned char *, unsigned char *)
  ]],c_pointers[8])

  sodium_lib.crypto_box_seed_keypair = ffi.cast([[
    int (*)(unsigned char *, unsigned char *, const unsigned char *)
  ]],c_pointers[9])

  sodium_lib.crypto_box_easy = ffi.cast([[
    int (*)(unsigned char *, const unsigned char *,
            unsigned long long, const unsigned char *,
            const unsigned char *, const unsigned char *)
  ]],c_pointers[10])

  sodium_lib.crypto_box_open_easy = ffi.cast([[
    int (*)(unsigned char *, const unsigned char *,
            unsigned long long, const unsigned char *,
            const unsigned char *, const unsigned char *)
  ]],c_pointers[11])

  sodium_lib.crypto_box_detached = ffi.cast([[
    int (*)(unsigned char *, unsigned char *,
            const unsigned char *,
            unsigned long long,
            const unsigned char *,
            const unsigned char *,
            const unsigned char *)
  ]],c_pointers[12])

  sodium_lib.crypto_box_open_detached = ffi.cast([[
    int (*)(unsigned char *,
            const unsigned char *,
            const unsigned char *,
            unsigned long long,
            const unsigned char *,
            const unsigned char *,
            const unsigned char *)
  ]],c_pointers[13])

  sodium_lib.crypto_box_beforenm = ffi.cast([[
    int (*)(unsigned char *, const unsigned char *,
            const unsigned char *)
  ]],c_pointers[14])

  sodium_lib.crypto_box_easy_afternm = ffi.cast([[
    int (*)(unsigned char *, const unsigned char *,
            unsigned long long, const unsigned char *,
            const unsigned char *)
  ]],c_pointers[15])

  sodium_lib.crypto_box_open_easy_afternm = ffi.cast([[
    int (*)(unsigned char *, const unsigned char *,
            unsigned long long, const unsigned char *,
            const unsigned char *)
  ]],c_pointers[16])

  sodium_lib.crypto_box_detached_afternm = ffi.cast([[
    int (*)(unsigned char *, unsigned char *,
            const unsigned char *, unsigned long long,
            const unsigned char *, const unsigned char *)
  ]],c_pointers[17])

  sodium_lib.crypto_box_open_detached_afternm = ffi.cast([[
    int (*)(unsigned char *, const unsigned char *,
            const unsigned char *, unsigned long long,
            const unsigned char *, const unsigned char *)
  ]],c_pointers[18])

else
  ffi.cdef([[
    int sodium_init(void);
    size_t crypto_box_publickeybytes(void);
    size_t crypto_box_secretkeybytes(void);
    size_t crypto_box_macbytes(void);
    size_t crypto_box_noncebytes(void);
    size_t crypto_box_seedbytes(void);
    size_t crypto_box_beforenmbytes(void);
  ]])
  do
    local ok, lib = pcall(test_cspace)
    if ok then
      sodium_lib = lib
    else
      sodium_lib = ffi.load('sodium')
    end
  end

  crypto_box_PUBLICKEYBYTES = tonumber(sodium_lib.crypto_box_publickeybytes())
  crypto_box_SECRETKEYBYTES = tonumber(sodium_lib.crypto_box_secretkeybytes())
  crypto_box_MACBYTES       = tonumber(sodium_lib.crypto_box_macbytes())
  crypto_box_NONCEBYTES     = tonumber(sodium_lib.crypto_box_noncebytes())
  crypto_box_SEEDBYTES      = tonumber(sodium_lib.crypto_box_seedbytes())
  crypto_box_BEFORENMBYTES  = tonumber(sodium_lib.crypto_box_beforenmbytes())

  ffi.cdef([[
    int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
    int crypto_box_seed_keypair(unsigned char *pk, unsigned char *sk,
                                 const unsigned char *seed);
    int crypto_box_easy(unsigned char *c, const unsigned char *m,
                    unsigned long long mlen, const unsigned char *n,
                    const unsigned char *pk, const unsigned char *sk);
    int crypto_box_open_easy(unsigned char *m, const unsigned char *c,
                         unsigned long long clen, const unsigned char *n,
                         const unsigned char *pk, const unsigned char *sk);
    int crypto_box_detached(unsigned char *c, unsigned char *mac,
                        const unsigned char *m,
                        unsigned long long mlen,
                        const unsigned char *n,
                        const unsigned char *pk,
                        const unsigned char *sk);
    int crypto_box_open_detached(unsigned char *m,
                             const unsigned char *c,
                             const unsigned char *mac,
                             unsigned long long clen,
                             const unsigned char *n,
                             const unsigned char *pk,
                             const unsigned char *sk);
    int crypto_box_beforenm(unsigned char *k, const unsigned char *pk,
                        const unsigned char *sk);
    int crypto_box_easy_afternm(unsigned char *c, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *n,
                            const unsigned char *k);

    int crypto_box_open_easy_afternm(unsigned char *m, const unsigned char *c,
                                 unsigned long long clen, const unsigned char *n,
                                 const unsigned char *k);

    int crypto_box_detached_afternm(unsigned char *c, unsigned char *mac,
                                const unsigned char *m, unsigned long long mlen,
                                const unsigned char *n, const unsigned char *k);

    int crypto_box_open_detached_afternm(unsigned char *m, const unsigned char *c,
                                     const unsigned char *mac,
                                     unsigned long long clen, const unsigned char *n,
                                     const unsigned char *k);
  ]])

end

local function lua_crypto_box_keypair()
  local pk = char_array(crypto_box_PUBLICKEYBYTES)
  local sk = char_array(crypto_box_SECRETKEYBYTES)
  if tonumber(sodium_lib.crypto_box_keypair(pk,sk)) == -1 then
    return error('crypto_box_keypair error')
  end
  return ffi_string(pk,crypto_box_PUBLICKEYBYTES),
         ffi_string(sk,crypto_box_SECRETKEYBYTES)
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
  return ffi_string(pk,crypto_box_PUBLICKEYBYTES),
         ffi_string(sk,crypto_box_SECRETKEYBYTES)
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

  return ffi_string(c,clen)
end

local function lua_crypto_box_open_easy(c,n,pk,sk)
  local m
  if not sk then
    return error('requires 4 arguments')
  end

  local clen = string_len(c)

  if clen < crypto_box_MACBYTES then
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
  if mlen == 0 then
    return ''
  end

  m = char_array(mlen)

  if tonumber(sodium_lib.crypto_box_open_easy(m,c,clen,n,pk,sk)) == -1 then
    return error('crypto_box_open_easy error')
  end

  return ffi_string(m,mlen)
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

  return ffi_string(c,mlen), ffi_string(mac,crypto_box_MACBYTES)
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

  if clen == 0 then
    return ''
  end

  m = char_array(clen)

  if tonumber(sodium_lib.crypto_box_open_detached(m,c,mac,clen,n,pk,sk)) == -1 then
    return error('crypto_box_open_detached error')
  end

  return ffi_string(m,clen)
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

  return ffi_string(k,crypto_box_BEFORENMBYTES)
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
    return error('crypto_box_easy_afternm error')
  end

  return ffi_string(c,clen)
end

local function lua_crypto_box_open_easy_afternm(c,n,k)
  local m

  if not k then
    return error('requires 3 arguments')
  end

  local clen = string_len(c)

  if clen < crypto_box_MACBYTES then
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
  if mlen == 0 then
    return ''
  end

  m = char_array(mlen)

  if tonumber(sodium_lib.crypto_box_open_easy_afternm(m,c,clen,n,k)) == -1 then
    return error('crypto_box_open_easy_afternm error')
  end

  return ffi_string(m,mlen)
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

  return ffi_string(c,mlen), ffi_string(mac,crypto_box_MACBYTES)
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

  return ffi_string(m,clen)
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end


local M = {
  crypto_box_PUBLICKEYBYTES = crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES = crypto_box_SECRETKEYBYTES,
  crypto_box_MACBYTES       = crypto_box_MACBYTES,
  crypto_box_NONCEBYTES     = crypto_box_NONCEBYTES,
  crypto_box_SEEDBYTES      = crypto_box_SEEDBYTES,
  crypto_box_BEFORENMBYTES  = crypto_box_BEFORENMBYTES,
  crypto_box_keypair = lua_crypto_box_keypair,
  crypto_box_seed_keypair = lua_crypto_box_seed_keypair,
  crypto_box_easy = lua_crypto_box_easy,
  crypto_box_open_easy = lua_crypto_box_open_easy,
  crypto_box_detached = lua_crypto_box_detached,
  crypto_box_open_detached = lua_crypto_box_open_detached,
  crypto_box_beforenm = lua_crypto_box_beforenm,
  crypto_box_easy_afternm = lua_crypto_box_easy_afternm,
  crypto_box_open_easy_afternm = lua_crypto_box_open_easy_afternm,
  crypto_box_detached_afternm = lua_crypto_box_detached_afternm,
  crypto_box_open_detached_afternm = lua_crypto_box_open_detached_afternm,
}

return M

