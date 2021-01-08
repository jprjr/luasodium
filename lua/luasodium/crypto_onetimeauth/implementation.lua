return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium
  local clib = libs.C

  local char_array = ffi.typeof('char[?]')

  local crypto_onetimeauth_BYTES = constants.crypto_onetimeauth_BYTES
  local crypto_onetimeauth_KEYBYTES = constants.crypto_onetimeauth_KEYBYTES
  local crypto_onetimeauth_STATEBYTES = tonumber(sodium_lib.crypto_onetimeauth_statebytes())

  local function ls_onetimeauth_free(state)
    sodium_lib.sodium_memzero(state,crypto_onetimeauth_STATEBYTES)
    clib.free(state)
  end

  local ls_crypto_onetimeauth_methods = {}
  local ls_crypto_onetimeauth_mt = {
    __index = ls_crypto_onetimeauth_methods,
  }

  local function ls_crypto_onetimeauth(message,key)
    if not key then
      return error('requires 2 arguments')
    end

    if string_len(key) ~= crypto_onetimeauth_KEYBYTES then
      return error(string_format(
        'wrong key size, expected: %d',
        crypto_onetimeauth_KEYBYTES))
    end

    local auth = char_array(crypto_onetimeauth_BYTES)
    if tonumber(sodium_lib.crypto_onetimeauth(
        auth,message,string_len(message),key)) == -1 then
        return error('crypto_onetimeauth error')
    end

    local auth_str = ffi_string(auth,crypto_onetimeauth_BYTES)
    sodium_lib.sodium_memzero(auth,crypto_onetimeauth_BYTES)
    return auth_str
  end

  local function ls_crypto_onetimeauth_verify(auth,message,key)
    if not key then
      return error('requires 3 arguments')
    end

    if string_len(auth) ~= crypto_onetimeauth_BYTES then
      return error(string_format(
        'wrong auth size, expected: %d',
        crypto_onetimeauth_BYTES))
    end

    if string_len(key) ~= crypto_onetimeauth_KEYBYTES then
      return error(string_format(
        'wrong key size, expected: %d',
        crypto_onetimeauth_KEYBYTES))
    end

    return tonumber(sodium_lib.crypto_onetimeauth_verify(
        auth,message,string_len(message),key)) ~= -1
  end

  local function ls_crypto_onetimeauth_keygen()
    local key = char_array(crypto_onetimeauth_KEYBYTES)
    sodium_lib.crypto_onetimeauth_keygen(key)
    local key_str = ffi_string(key,crypto_onetimeauth_KEYBYTES)
    sodium_lib.sodium_memzero(key,crypto_onetimeauth_KEYBYTES)
    return key_str
  end

  local function ls_crypto_onetimeauth_init(key)
    if not key then
      return error('requires 1 parameter')
    end

    if string_len(key) ~= crypto_onetimeauth_KEYBYTES then
      return error(string_format(
        'wrong key size, expected: %d',
        crypto_onetimeauth_KEYBYTES
      ))
    end

    local state = ffi.gc(clib.malloc(crypto_onetimeauth_STATEBYTES),ls_onetimeauth_free)
    if tonumber(sodium_lib.crypto_onetimeauth_init(state,key)) == -1 then
      return error('crypto_onetimeauth_init error')
    end
    return setmetatable({
      state = state
    }, ls_crypto_onetimeauth_mt)
  end

  local function ls_crypto_onetimeauth_update(ls_state,m)
    if not m then
      return error('requires 2 parameters')
    end

    local mt = getmetatable(ls_state)
    if mt ~= ls_crypto_onetimeauth_mt then
      return error('invalid userdata')
    end

    return tonumber(sodium_lib.crypto_onetimeauth_update(
      ls_state.state,m,string_len(m))) ~= -1
  end

  local function ls_crypto_onetimeauth_final(ls_state)
    if not ls_state then
      return error('requires 1 parameter')
    end

    local mt = getmetatable(ls_state)
    if mt ~= ls_crypto_onetimeauth_mt then
      return error('invalid userdata')
    end

    local auth = char_array(crypto_onetimeauth_BYTES)
    if tonumber(sodium_lib.crypto_onetimeauth_final(
      ls_state.state,auth)) == -1 then
      return error('crypto_onetimeauth_final error')
    end

    local auth_str = ffi_string(auth,crypto_onetimeauth_BYTES)
    sodium_lib.sodium_memzero(auth,crypto_onetimeauth_BYTES)
    return auth_str
  end

  ls_crypto_onetimeauth_methods.update = ls_crypto_onetimeauth_update
  ls_crypto_onetimeauth_methods.final = ls_crypto_onetimeauth_final

  local M = {
    crypto_onetimeauth = ls_crypto_onetimeauth,
    crypto_onetimeauth_verify = ls_crypto_onetimeauth_verify,
    crypto_onetimeauth_keygen = ls_crypto_onetimeauth_keygen,
    crypto_onetimeauth_init = ls_crypto_onetimeauth_init,
    crypto_onetimeauth_update = ls_crypto_onetimeauth_update,
    crypto_onetimeauth_final = ls_crypto_onetimeauth_final,
  }

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end


