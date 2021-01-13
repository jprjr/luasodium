return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium
  local clib = libs.C

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_secretstream(basename)
    local crypto_secretstream_init_push = string_format('%s_init_push',basename)
    local crypto_secretstream_keygen = string_format('%s_keygen',basename)

    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local HEADERBYTES = constants[string_format('%s_HEADERBYTES',basename)]
    local STATEBYTES = tonumber(sodium_lib[string_format('%s_statebytes',basename)]())

    local ls_crypto_secretstream_free = function(state)
      sodium_lib.sodium_memzero(state,STATEBYTES)
      clib.free(state)
    end

    local ls_crypto_secretstream_methods = {}
    local ls_crypto_secretstream_mt = {
      __index = ls_crypto_secretstream_methods
    }

    local M = {
      [crypto_secretstream_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib[crypto_secretstream_keygen](k)
        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,

      [crypto_secretstream_init_push] = function(key)
        if not key then
          return error('requires 1 argument')
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
            'wrong key size, expected: %d',
            KEYBYTES))
        end

        local state = ffi.gc(clib.malloc(STATEBYTES),ls_crypto_secretstream_free)
        local header = char_array(HEADERBYTES)

        if tonumber(sodium_lib[crypto_secretstream_init_push](state,header,key)) == -1 then
          return error(string_format('%s error', crypto_secretstream_init_push))
        end

        local ls_state = setmetatable({
          state = state,
        },ls_crypto_secretstream_mt)

        local header_str = ffi_string(header,HEADERBYTES)
        sodium_lib.sodium_memzero(header,HEADERBYTES)

        return ls_state, header_str
      end,

    }

    return M
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

