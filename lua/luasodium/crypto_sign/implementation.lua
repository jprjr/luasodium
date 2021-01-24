return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string

  local char_array = ffi.typeof('char[?]')

  local sodium_lib = libs.sodium
  local clib = libs.C

  -- handles the main 3 functions - keypair, sign, open
  local function ls_crypto_sign(basename)
    local crypto_sign      = string_format('%s',basename)
    local crypto_sign_open = string_format('%s_open',basename)
    local crypto_sign_keypair = string_format('%s_keypair',basename)
    local PUBLICKEYBYTES = constants[string_format('%s_PUBLICKEYBYTES',basename)]
    local SECRETKEYBYTES = constants[string_format('%s_SECRETKEYBYTES',basename)]
    local BYTES          = constants[string_format('%s_BYTES',basename)]

    return {
      [crypto_sign] = function (m,sk)
        if not sk then
          return error('requires 2 parameters')
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format('wrong secret key size, expected: %d',
            SECRETKEYBYTES))
        end

        local mlen = string_len(m)

        local sm = char_array(mlen + BYTES)
        local smlen = ffi.new('size_t[1]')

        if tonumber(sodium_lib[crypto_sign](sm,smlen,m,mlen,sk)) == -1 then
          return error(string_format('%s error',crypto_sign))
        end

        local sm_str = ffi_string(sm,smlen[0])
        sodium_lib.sodium_memzero(sm,mlen + BYTES)
        return sm_str
      end,

      [crypto_sign_open] = function(sm,pk)
        local m_str
        if not pk then
          return error('requires 2 parameters')
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format('wrong public key size, expected: %d',
            PUBLICKEYBYTES))
        end

        local smlen = string_len(sm)

        local m = char_array(smlen)
        local mlen = ffi.new('size_t[1]')

        if tonumber(sodium_lib[crypto_sign_open](m,mlen,sm,smlen,pk)) == 0 then
          m_str = ffi_string(m,mlen[0])
        end

        sodium_lib.sodium_memzero(m,smlen)
        return m_str
      end,

      [crypto_sign_keypair] = function()
        local pk = char_array(PUBLICKEYBYTES)
        local sk = char_array(SECRETKEYBYTES)

        if tonumber(sodium_lib[crypto_sign_keypair](pk,sk)) == -1 then
          return error(string_format('%s error',crypto_sign_keypair))
        end

        local pk_str = ffi_string(pk,PUBLICKEYBYTES)
        local sk_str = ffi_string(sk,SECRETKEYBYTES)

        sodium_lib.sodium_memzero(pk,PUBLICKEYBYTES)
        sodium_lib.sodium_memzero(sk,SECRETKEYBYTES)

        return pk_str, sk_str
      end,
    }
  end

  -- handles detached and verify_detached
  local function ls_crypto_sign_detached(basename)
    local crypto_sign_detached        = string_format('%s_detached',basename)
    local crypto_sign_verify_detached = string_format('%s_verify_detached',basename)
    local PUBLICKEYBYTES = constants[string_format('%s_PUBLICKEYBYTES',basename)]
    local SECRETKEYBYTES = constants[string_format('%s_SECRETKEYBYTES',basename)]

    return {
      [crypto_sign_detached] = function(m, sk)
        if not sk then
          return error('requires 2 parameters')
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format('wrong secret key size, expected: %d',
            SECRETKEYBYTES))
        end

        local mlen = string_len(m)

        local sig = char_array(SECRETKEYBYTES)
        local siglen = ffi.new('size_t[1]')

        if tonumber(sodium_lib[crypto_sign_detached](sig,siglen,m,mlen,sk)) == -1 then
          return error(string_format('%s error',crypto_sign_detached))
        end

        local sig_str = ffi_string(sig,siglen[0])
        sodium_lib.sodium_memzero(sig,SECRETKEYBYTES)
        return sig_str
      end,

      [crypto_sign_verify_detached] = function(sig,m,pk)
        if not pk then
          return error('requires 3 parameters')
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format('wrong public key size, expected: %d',
            PUBLICKEYBYTES))
        end

        return tonumber(sodium_lib[crypto_sign_verify_detached](
          sig,m,string_len(m),pk)) == 0
      end,
    }
  end

  -- handles setting up a state object, can't automatically generate values
  -- for BYTES since prefix of state (crypto_sign_ed25519ph) may not match
  -- prefix of values (crypto_sign_PUBLICKEYBYTES)
  local function ls_crypto_sign_state(basename,PUBLICKEYBYTES,SECRETKEYBYTES,BYTES)
    local crypto_sign_init = string_format('%s_init',basename)
    local crypto_sign_update = string_format('%s_update',basename)
    local crypto_sign_final_create = string_format('%s_final_create',basename)
    local crypto_sign_final_verify = string_format('%s_final_verify',basename)
    local STATEBYTES = tonumber(sodium_lib[string_format('%s_statebytes',basename)]())

    local ls_crypto_sign_free = function(state)
      sodium_lib.sodium_memzero(state,STATEBYTES)
      clib.free(state)
    end

    local ls_crypto_sign_methods = {}
    local ls_crypto_sign_mt = {
      __index = ls_crypto_sign_methods
    }

    local M = {
      [crypto_sign_init] = function()
        local state = ffi.gc(clib.malloc(STATEBYTES),ls_crypto_sign_free)
        if tonumber(sodium_lib[crypto_sign_init](state)) == -1 then
          return error(string_format('%s error', crypto_sign_init))
        end

        return setmetatable({
          state = state
        }, ls_crypto_sign_mt)
      end,

      [crypto_sign_update] = function(ls_state,m)
        if not m then
          return error('requires 2 parameters')
        end

        local mt = getmetatable(ls_state)
        if mt ~= ls_crypto_sign_mt then
          return error('invalid userdata')
        end

        return tonumber(sodium_lib[crypto_sign_update](
          ls_state.state,m,string_len(m))) ~= -1
      end,

      [crypto_sign_final_create] = function(ls_state,sk)
        if not sk then
          return error('requires 2 parameters')
        end

        local mt = getmetatable(ls_state)
        if mt ~= ls_crypto_sign_mt then
          return error('invalid userdata')
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format('wrong secret key size, expected: %d',
            SECRETKEYBYTES))
        end

        local sig = char_array(BYTES)
        local siglen = ffi.new('size_t[1]')

        if tonumber(sodium_lib[crypto_sign_final_create](
          ls_state.state,sig,siglen,sk)) == -1 then
          return error(string_format('%s error',crypto_sign_final_create))
        end

        local sig_str = ffi_string(sig,siglen[0])
        sodium_lib.sodium_memzero(sig,BYTES)
        return sig_str
      end,

      [crypto_sign_final_verify] = function(ls_state,sig,pk)
        if not pk then
          return error('requires 3 parameters')
        end

        local mt = getmetatable(ls_state)
        if mt ~= ls_crypto_sign_mt then
          return error('invalid userdata')
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format('wrong public key size, expected: %d',
            PUBLICKEYBYTES))
        end

        return tonumber(sodium_lib[crypto_sign_final_verify](
          ls_state.state,sig,pk)) == 0

      end,
    }

    ls_crypto_sign_methods.update = M[crypto_sign_update]
    ls_crypto_sign_methods.final_create = M[crypto_sign_final_create]
    ls_crypto_sign_methods.final_verify = M[crypto_sign_final_verify]

    return M

  end

  local function ls_crypto_sign_seed_keypair(basename)
    local crypto_sign_seed_keypair = string_format('%s_seed_keypair',basename)
    local PUBLICKEYBYTES = constants[string_format('%s_PUBLICKEYBYTES',basename)]
    local SECRETKEYBYTES = constants[string_format('%s_SECRETKEYBYTES',basename)]
    local SEEDBYTES      = constants[string_format('%s_SEEDBYTES',basename)]

    return {
      [crypto_sign_seed_keypair] = function(seed)
        if not seed then
          return error('requires 1 parameter')
        end

        if string_len(seed) ~= SEEDBYTES then
          return error(string_format('wrong seed size, expected: %d',
            SEEDBYTES))
        end

        local pk = char_array(PUBLICKEYBYTES)
        local sk = char_array(SECRETKEYBYTES)

        if tonumber(sodium_lib[crypto_sign_seed_keypair](pk,sk,seed)) == -1 then
          return error(string_format('%s error',crypto_sign_seed_keypair))
        end

        local pk_str = ffi_string(pk,PUBLICKEYBYTES)
        local sk_str = ffi_string(sk,SECRETKEYBYTES)

        sodium_lib.sodium_memzero(pk,PUBLICKEYBYTES)
        sodium_lib.sodium_memzero(sk,SECRETKEYBYTES)

        return pk_str, sk_str

      end,
    }
  end

  local function ls_crypto_sign_sk(basename)
    local crypto_sign_sk_to_seed = string_format('%s_sk_to_seed',basename)
    local crypto_sign_sk_to_pk = string_format('%s_sk_to_pk',basename)
    local PUBLICKEYBYTES = constants[string_format('%s_PUBLICKEYBYTES',basename)]
    local SECRETKEYBYTES = constants[string_format('%s_SECRETKEYBYTES',basename)]
    local SEEDBYTES      = constants[string_format('%s_SEEDBYTES',basename)]

    return {
      [crypto_sign_sk_to_seed] = function(sk)
        if not sk then
          return error('requires 1 parameter')
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string.format('wrong secret key size, expected: %d',
            SECRETKEYBYTES))
        end

        local seed = char_array(SEEDBYTES)

        if tonumber(sodium_lib[crypto_sign_sk_to_seed](
          seed,sk)) == -1 then
          return error(string_format('%s error',crypto_sign_sk_to_seed))
        end
        local seed_str = ffi_string(seed,SEEDBYTES)
        sodium_lib.sodium_memzero(seed,SEEDBYTES)
        return seed_str
      end,

      [crypto_sign_sk_to_pk] = function(sk)
        if not sk then
          return error('requires 1 parameter')
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string.format('wrong secret key size, expected: %d',
            SECRETKEYBYTES))
        end

        local pk = char_array(PUBLICKEYBYTES)

        if tonumber(sodium_lib[crypto_sign_sk_to_pk](
          pk,sk)) == -1 then
          return error(string_format('%s error',crypto_sign_sk_to_pk))
        end
        local pk_str = ffi_string(pk,PUBLICKEYBYTES)
        sodium_lib.sodium_memzero(pk,PUBLICKEYBYTES)
        return pk_str
      end,
    }

  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = { }

  for _,basename in pairs({
    'crypto_sign',
    'crypto_sign_ed25519',
  }) do
    local m = ls_crypto_sign(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for _,basename in pairs({
    'crypto_sign',
    'crypto_sign_ed25519',
  }) do
    local m = ls_crypto_sign_detached(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for _,basename in pairs({
    'crypto_sign',
    'crypto_sign_ed25519',
  }) do
    local m = ls_crypto_sign_seed_keypair(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for _,basename in pairs({
    'crypto_sign_ed25519',
  }) do
    local m = ls_crypto_sign_sk(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  do
    local m = ls_crypto_sign_state('crypto_sign',
      constants.crypto_sign_PUBLICKEYBYTES,
      constants.crypto_sign_SECRETKEYBYTES,
      constants.crypto_sign_BYTES)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  do
    local m = ls_crypto_sign_state('crypto_sign_ed25519ph',
      constants.crypto_sign_PUBLICKEYBYTES,
      constants.crypto_sign_SECRETKEYBYTES,
      constants.crypto_sign_BYTES)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
