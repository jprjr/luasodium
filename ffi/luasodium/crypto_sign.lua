local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string
local type = type

local char_array = ffi.typeof('char[?]')

local constants
local sodium_lib

local constant_keys = {
  'crypto_sign_PUBLICKEYBYTES',
  'crypto_sign_SECRETKEYBYTES',
  'crypto_sign_BYTES',
  'crypto_sign_SEEDBYTES',
  'crypto_sign_STATEBYTES', -- not an actual const in libsodium,
                            -- but this way we use the usual code
                            -- to grab it
}

local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],
  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],
  ['crypto_sign_keypair'] = [[
    int %s(unsigned char *pk, unsigned char *sk)

  ]],
  ['crypto_sign_seed_keypair'] = [[
    int %s(unsigned char *pk, unsigned char *sk,
           const unsigned char *seed)
  ]],
  ['crypto_sign'] = [[
    int %s(unsigned char *sm, unsigned long long *smlen_p,
           const unsigned char *m, unsigned long long mlen,
           const unsigned char *sk)
  ]],
  ['crypto_sign_open'] = [[
  int %s(unsigned char *m, unsigned long long *mlen_p,
         const unsigned char *sm, unsigned long long smlen,
         const unsigned char *pk)
  ]],
  ['crypto_sign_detached'] = [[
  int %s(unsigned char *sig, unsigned long long *siglen_p,
         const unsigned char *m, unsigned long long mlen,
         const unsigned char *sk)
  ]],
  ['crypto_sign_verify_detached'] = [[
    int %s(const unsigned char *sig, const unsigned char *m,
           unsigned long long mlen, const unsigned char *pk)
  ]],
  ['crypto_sign_init'] = [[
    int %s(void *state)
  ]],
  ['crypto_sign_update'] = [[
    int %s(void *state, const unsigned char *m, unsigned long long mlen)
  ]],
  ['crypto_sign_final_create'] = [[
    int %s(void *state, unsigned char *sig,
           unsigned long long *siglen_p, const unsigned char *sk)
  ]],
  ['crypto_sign_final_verify'] = [[
    int %s(void *state, const unsigned char *sig,
           const unsigned char *pk)
  ]],
  ['crypto_sign_ed25519_sk_to_seed'] = [[
    int %s(unsigned char *seed, const unsigned char *sk)
  ]],
  ['crypto_sign_ed25519_sk_to_pk'] = [[
    int %s(unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_sign_statebytes'] = [[
    size_t %s(void)
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

local crypto_sign_PUBLICKEYBYTES = constants.crypto_sign_PUBLICKEYBYTES
local crypto_sign_SECRETKEYBYTES = constants.crypto_sign_SECRETKEYBYTES
local crypto_sign_BYTES          = constants.crypto_sign_BYTES
local crypto_sign_SEEDBYTES      = constants.crypto_sign_SEEDBYTES
local crypto_sign_STATEBYTES     = constants.crypto_sign_STATEBYTES

local function ls_crypto_sign_keypair()
  local pk = char_array(crypto_sign_PUBLICKEYBYTES)
  local sk = char_array(crypto_sign_SECRETKEYBYTES)

  if tonumber(sodium_lib.crypto_sign_keypair(pk,sk)) == -1 then
    return error('crypto_sign_keypair error')
  end

  local pk_str = ffi_string(pk,crypto_sign_PUBLICKEYBYTES)
  local sk_str = ffi_string(sk,crypto_sign_SECRETKEYBYTES)

  sodium_lib.sodium_memzero(pk,crypto_sign_PUBLICKEYBYTES)
  sodium_lib.sodium_memzero(sk,crypto_sign_SECRETKEYBYTES)

  return pk_str, sk_str
end

local function ls_crypto_sign_seed_keypair(seed)
  if not seed then
    return error('requires 1 parameter')
  end

  if string_len(seed) ~= crypto_sign_SEEDBYTES then
    return error(string_format('wrong seed size, expected: %d',
      crypto_sign_SEEDBYTES))
  end

  local pk = char_array(crypto_sign_PUBLICKEYBYTES)
  local sk = char_array(crypto_sign_SECRETKEYBYTES)

  if tonumber(sodium_lib.crypto_sign_seed_keypair(pk,sk,seed)) == -1 then
    return error('crypto_sign_seed_keypair error')
  end

  local pk_str = ffi_string(pk,crypto_sign_PUBLICKEYBYTES)
  local sk_str = ffi_string(sk,crypto_sign_SECRETKEYBYTES)

  sodium_lib.sodium_memzero(pk,crypto_sign_PUBLICKEYBYTES)
  sodium_lib.sodium_memzero(sk,crypto_sign_SECRETKEYBYTES)

  return pk_str, sk_str
end

local function ls_crypto_sign(m,sk)
  if not sk then
    return error('requires 2 parameters')
  end

  if string_len(sk) ~= crypto_sign_SECRETKEYBYTES then
    return error(string_format('wrong secret key size, expected: %d',
      crypto_sign_SECRETKEYBYTES))
  end

  local mlen = string_len(m)

  local sm = char_array(mlen + crypto_sign_BYTES)
  local smlen = ffi.new('size_t[1]')

  if tonumber(sodium_lib.crypto_sign(sm,smlen,m,mlen,sk)) == -1 then
    return error('crypto_sign error')
  end

  local sm_str = ffi_string(sm,smlen[0])
  sodium_lib.sodium_memzero(sm,mlen + crypto_sign_BYTES)
  return sm_str
end

local function ls_crypto_sign_open(sm,pk)
  local m_str
  if not pk then
    return error('requires 2 parameters')
  end

  if string_len(pk) ~= crypto_sign_PUBLICKEYBYTES then
    return error(string_format('wrong public key size, expected: %d',
      crypto_sign_PUBLICKEYBYTES))
  end

  local smlen = string_len(sm)

  local m = char_array(smlen)
  local mlen = ffi.new('size_t[1]')

  if tonumber(sodium_lib.crypto_sign_open(m,mlen,sm,smlen,pk)) == 0 then
    m_str = ffi_string(m,mlen[0])
  end

  sodium_lib.sodium_memzero(m,smlen)
  return m_str
end

local function ls_crypto_sign_detached(m,sk)
  if not sk then
    return error('requires 2 parameters')
  end

  if string_len(sk) ~= crypto_sign_SECRETKEYBYTES then
    return error(string_format('wrong secret key size, expected: %d',
      crypto_sign_SECRETKEYBYTES))
  end

  local mlen = string_len(m)

  local sig = char_array(crypto_sign_SECRETKEYBYTES)
  local siglen = ffi.new('size_t[1]')

  if tonumber(sodium_lib.crypto_sign_detached(sig,siglen,m,mlen,sk)) == -1 then
    return error('crypto_sign_detached error')
  end

  local sig_str = ffi_string(sig,siglen[0])
  sodium_lib.sodium_memzero(sig,crypto_sign_SECRETKEYBYTES)
  return sig_str
end

local function ls_crypto_sign_verify_detached(sig,m,pk)
  if not pk then
    return error('requires 3 parameters')
  end

  if string_len(pk) ~= crypto_sign_PUBLICKEYBYTES then
    return error(string_format('wrong public key size, expected: %d',
      crypto_sign_PUBLICKEYBYTES))
  end

  return tonumber(sodium_lib.crypto_sign_verify_detached(
    sig,m,string_len(m),pk)) == 0
end

local function ls_crypto_sign_init()
  local state = char_array(crypto_sign_STATEBYTES)
  if tonumber(sodium_lib.crypto_sign_init(state)) == -1 then
    return error('crypto_sign_init error')
  end
  return state
end

local function ls_crypto_sign_update(state,m)
  if not m then
    return error('requires 2 parameters')
  end

  return tonumber(sodium_lib.crypto_sign_update(
    state,m,string_len(m))) ~= -1
end

local function ls_crypto_sign_final_create(state,sk)
  if not sk then
    return error('requires 2 parameters')
  end

  if string_len(sk) ~= crypto_sign_SECRETKEYBYTES then
    return error(string_format('wrong secret key size, expected: %d',
      crypto_sign_SECRETKEYBYTES))
  end

  local sig = char_array(crypto_sign_BYTES)
  local siglen = ffi.new('size_t[1]')

  if tonumber(sodium_lib.crypto_sign_final_create(
    state,sig,siglen,sk)) == -1 then
    return error('crypto_sign_final_create error')
  end

  local sig_str = ffi_string(sig,siglen[0])
  sodium_lib.sodium_memzero(sig,crypto_sign_BYTES)
  return sig_str
end

local function ls_crypto_sign_final_verify(state,sig,pk)
  if not pk then
    return error('requires 3 parameters')
  end

  if string_len(pk) ~= crypto_sign_PUBLICKEYBYTES then
    return error(string_format('wrong secret key size, expected: %d',
      crypto_sign_PUBLICKEYBYTES))
  end

  return tonumber(sodium_lib.crypto_sign_final_verify(
    state,sig,pk)) == 0
end

local function ls_crypto_sign_ed25519_sk_to_seed(sk)
  if not sk then
    return error('requires 1 parameter')
  end

  local seed = char_array(crypto_sign_SEEDBYTES)

  if tonumber(sodium_lib.crypto_sign_ed25519_sk_to_seed(
    seed,sk)) == -1 then
    return error('crypto_sign_ed25519_sk_to_seed error')
  end
  local seed_str = ffi_string(seed,crypto_sign_SEEDBYTES)
  sodium_lib.sodium_memzero(seed,crypto_sign_SEEDBYTES)
  return seed_str
end

local function ls_crypto_sign_ed25519_sk_to_pk(sk)
  if not sk then
    return error('requires 1 parameter')
  end

  local pk = char_array(crypto_sign_PUBLICKEYBYTES)

  if tonumber(sodium_lib.crypto_sign_ed25519_sk_to_pk(
    pk,sk)) == -1 then
    return error('crypto_sign_ed25519_sk_to_pk error')
  end
  local pk_str = ffi_string(pk,crypto_sign_PUBLICKEYBYTES)
  sodium_lib.sodium_memzero(pk,crypto_sign_PUBLICKEYBYTES)
  return pk_str
end

local M = {
  crypto_sign_keypair = ls_crypto_sign_keypair,
  crypto_sign_seed_keypair = ls_crypto_sign_seed_keypair,
  crypto_sign = ls_crypto_sign,
  crypto_sign_open= ls_crypto_sign_open,
  crypto_sign_detached = ls_crypto_sign_detached,
  crypto_sign_verify_detached = ls_crypto_sign_verify_detached,
  crypto_sign_init = ls_crypto_sign_init,
  crypto_sign_update = ls_crypto_sign_update,
  crypto_sign_final_create = ls_crypto_sign_final_create,
  crypto_sign_final_verify = ls_crypto_sign_final_verify,
  crypto_sign_ed25519_sk_to_seed = ls_crypto_sign_ed25519_sk_to_seed,
  crypto_sign_ed25519_sk_to_pk = ls_crypto_sign_ed25519_sk_to_pk,
}

for k,v in pairs(constants) do
  M[k] = v
end

return M
