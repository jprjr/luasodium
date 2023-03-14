return function(sodium_lib, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_kx(basename)
    local crypto_kx_keypair = string_format('%s_keypair',basename)
    local crypto_kx_seed_keypair = string_format('%s_seed_keypair',basename)
    local crypto_kx_client_session_keys = string_format('%s_client_session_keys',basename)
    local crypto_kx_server_session_keys = string_format('%s_server_session_keys',basename)

    local PUBLICKEYBYTES = constants[string_format('%s_PUBLICKEYBYTES',basename)]
    local SECRETKEYBYTES = constants[string_format('%s_SECRETKEYBYTES',basename)]
    local SEEDBYTES = constants[string_format('%s_SEEDBYTES',basename)]
    local SESSIONKEYBYTES = constants[string_format('%s_SESSIONKEYBYTES',basename)]

    return {
      [crypto_kx_keypair] = function()
        local pk = char_array(PUBLICKEYBYTES)
        local sk = char_array(SECRETKEYBYTES)

        if tonumber(sodium_lib[crypto_kx_keypair](pk,sk)) == -1 then
          return nil, string_format('%s error', crypto_kx_keypair)
        end

        local pk_str = ffi_string(pk,PUBLICKEYBYTES)
        local sk_str = ffi_string(sk,PUBLICKEYBYTES)
        sodium_lib.sodium_memzero(pk, PUBLICKEYBYTES)
        sodium_lib.sodium_memzero(sk, SECRETKEYBYTES)
        return pk_str, sk_str
      end,

      [crypto_kx_seed_keypair] = function(seed)
        if not seed then
          return error('requires 1 argument')
        end
        if string_len(seed) ~= SEEDBYTES then
          return error(string_format('wrong seed size, expected: %d', SEEDBYTES))
        end

        local pk = char_array(PUBLICKEYBYTES)
        local sk = char_array(SECRETKEYBYTES)

        if tonumber(sodium_lib[crypto_kx_seed_keypair](pk,sk,seed)) == -1 then
          return nil, string_format('%s error', crypto_kx_keypair)
        end

        local pk_str = ffi_string(pk,PUBLICKEYBYTES)
        local sk_str = ffi_string(sk,PUBLICKEYBYTES)

        sodium_lib.sodium_memzero(pk, PUBLICKEYBYTES)
        sodium_lib.sodium_memzero(sk, SECRETKEYBYTES)

        return pk_str, sk_str
      end,

      [crypto_kx_client_session_keys] = function(client_pk, client_sk, server_pk)
        if not server_pk then
          return error('requires 3 arguments')
        end
        if string_len(client_pk) ~= PUBLICKEYBYTES then
          return error('wrong client public key size, expected: %d',
            PUBLICKEYBYTES)
        end
        if string_len(client_sk) ~= SECRETKEYBYTES then
          return error('wrong client secret key size, expected: %d',
            SECRETKEYBYTES)
        end
        if string_len(server_pk) ~= PUBLICKEYBYTES then
          return error('wrong server public key size, expected: %d',
            PUBLICKEYBYTES)
        end

        local rx = char_array(SESSIONKEYBYTES)
        local tx = char_array(SESSIONKEYBYTES)

        if tonumber(sodium_lib[crypto_kx_client_session_keys](rx,tx,client_pk,client_sk,server_pk)) == -1 then
          return nil, string_format('%s error',crypto_kx_client_session_keys)
        end

        local rx_str = ffi_string(rx, SESSIONKEYBYTES)
        local tx_str = ffi_string(tx, SESSIONKEYBYTES)

        sodium_lib.sodium_memzero(rx, SESSIONKEYBYTES)
        sodium_lib.sodium_memzero(tx, SESSIONKEYBYTES)

        return rx_str, tx_str
      end,

      [crypto_kx_server_session_keys] = function(server_pk, server_sk, client_pk)
        if not client_pk then
          return error('requires 3 arguments')
        end
        if string_len(server_pk) ~= PUBLICKEYBYTES then
          return error('wrong server public key size, expected: %d',
            PUBLICKEYBYTES)
        end
        if string_len(server_sk) ~= SECRETKEYBYTES then
          return error('wrong server secret key size, expected: %d',
            SECRETKEYBYTES)
        end
        if string_len(client_pk) ~= PUBLICKEYBYTES then
          return error('wrong client public key size, expected: %d',
            PUBLICKEYBYTES)
        end

        local rx = char_array(SESSIONKEYBYTES)
        local tx = char_array(SESSIONKEYBYTES)

        if tonumber(sodium_lib[crypto_kx_server_session_keys](rx,tx,server_pk,server_sk,client_pk)) == -1 then
          return nil, string_format('%s error',crypto_kx_server_session_keys)
        end

        local rx_str = ffi_string(rx, SESSIONKEYBYTES)
        local tx_str = ffi_string(tx, SESSIONKEYBYTES)

        sodium_lib.sodium_memzero(rx, SESSIONKEYBYTES)
        sodium_lib.sodium_memzero(tx, SESSIONKEYBYTES)

        return rx_str, tx_str
      end,
    }

  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = {}

  for _,basename in ipairs({
    'crypto_kx',
  }) do
    local m = ls_crypto_kx(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
