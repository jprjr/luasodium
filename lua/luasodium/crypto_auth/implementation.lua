return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_auth(basename)
    local crypto_auth = string_format('%s',basename)
    local crypto_auth_verify = string_format('%s_verify',basename)
    local crypto_auth_keygen = string_format('%s_keygen',basename)
    local BYTES = constants[string_format('%s_BYTES',basename)]
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]

    return {
      [crypto_auth] = function(message,key)
        if not key then
          return error('requires 2 arguments')
        end

        if string_len(key) ~= KEYBYTES then
          return error('wrong key length, expected %d', KEYBYTES)
        end

        local out = char_array(BYTES)
        if tonumber(sodium_lib[crypto_auth](
          out,message,string_len(message),key)) == -1 then
          return nil, string_format('%s error',crypto_auth)
        end

        local out_str = ffi_string(out,BYTES)
        sodium_lib.sodium_memzero(out,BYTES)
        return out_str
      end,

      [crypto_auth_verify] = function(tag,message,key)
        if not key then
          return error('requires 3 arguments')
        end

        if string_len(key) ~= KEYBYTES then
          return error('wrong key length, expected %d', KEYBYTES)
        end

        return tonumber(sodium_lib[crypto_auth_verify](
          tag, message, string_len(message), key)) == 0

      end,

      [crypto_auth_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib[crypto_auth_keygen](k)
        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,
    }
  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = {}

  for _,basename in ipairs({
      'crypto_auth',
      'crypto_auth_hmacsha256',
      'crypto_auth_hmacsha512256',
      'crypto_auth_hmacsha512',
  }) do
    local m = ls_crypto_auth(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
