return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_secretstream(basename)
    local crypto_secretstream_keygen = string_format('%s_keygen',basename)
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]

    return {
      [crypto_secretstream_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib[crypto_secretstream_keygen](k)
        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,
    }
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_secretstream_xchacha20poly1305',
  }) do
    local m = ls_crypto_secretstream(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end

