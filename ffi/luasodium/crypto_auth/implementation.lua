return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local ffi_string = ffi.string

  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  local crypto_auth_BYTES = constants.crypto_auth_BYTES
  local crypto_auth_KEYBYTES = constants.crypto_auth_KEYBYTES

  local function ls_crypto_auth(message,key)
    if not key then
      return error('requires 2 arguments')
    end

    if string_len(key) ~= crypto_auth_KEYBYTES then
      return error('wrong key length, expected %d', crypto_auth_KEYBYTES)
    end

    local out = char_array(crypto_auth_BYTES)
    if tonumber(sodium_lib.crypto_auth(
      out,message,string_len(message),key)) == -1 then
      return error('crypto_auth error')
    end

    local out_str = ffi_string(out,crypto_auth_BYTES)
    sodium_lib.sodium_memzero(out,crypto_auth_BYTES)
    return out_str

  end

  local function ls_crypto_auth_verify(tag,message,key)
    if not key then
      return error('requires 3 arguments')
    end

    if string_len(key) ~= crypto_auth_KEYBYTES then
      return error('wrong key length, expected %d', crypto_auth_KEYBYTES)
    end

    return tonumber(sodium_lib.crypto_auth_verify(
      tag, message, string_len(message), key)) == 0
  end

  local function ls_crypto_auth_keygen()
    local k = char_array(crypto_auth_KEYBYTES)
    sodium_lib.crypto_auth_keygen(k)
    local k_str = ffi_string(k,crypto_auth_KEYBYTES)
    sodium_lib.sodium_memzero(k,crypto_auth_KEYBYTES)
    return k_str
  end

  if sodium_lib.sodium_init() == -1 then
    return error('sodium_init error')
  end

  local M = {
    crypto_auth = ls_crypto_auth,
    crypto_auth_verify = ls_crypto_auth_verify,
    crypto_auth_keygen = ls_crypto_auth_keygen,
  }

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
