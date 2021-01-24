return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_shorthash_keygen(basename)
    local crypto_shorthash_keygen = string_format('%s_keygen',basename)
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]

    local M = {
      [crypto_shorthash_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib[crypto_shorthash_keygen](k)
        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,
    }

    return M

  end

  local function ls_crypto_shorthash(basename)
    local crypto_shorthash = string_format('%s',basename)
    local BYTES = constants[string_format('%s_BYTES',basename)]
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]

    local M = {
      [crypto_shorthash] = function(message, key)
        local out

        if not key then
          return error('requires 2 parameters')
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
              'wrong key size, expected: %d', KEYBYTES))
        end

        out = char_array(BYTES)

        if tonumber(sodium_lib[crypto_shorthash](
          out,message,string_len(message),key)) == -1 then
          return error(string_format('%s error',crypto_shorthash))
        end

        local out_str = ffi_string(out,BYTES)
        sodium_lib.sodium_memzero(out,BYTES)
        return out_str
      end,

    }

    return M
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_shorthash',
    'crypto_shorthash_siphashx24',
  }) do
    local m = ls_crypto_shorthash(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for _,basename in ipairs({
    'crypto_shorthash',
  }) do
    local m = ls_crypto_shorthash_keygen(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end


