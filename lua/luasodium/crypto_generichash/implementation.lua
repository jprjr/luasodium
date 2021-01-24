return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium
  local clib = libs.C

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_generichash(basename)
    local crypto_generichash_keygen = string_format('%s_keygen',basename)
    local crypto_generichash = string_format('%s',basename)
    local crypto_generichash_init = string_format('%s_init',basename)
    local crypto_generichash_update = string_format('%s_update',basename)
    local crypto_generichash_final = string_format('%s_final',basename)

    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local KEYBYTES_MIN = constants[string_format('%s_KEYBYTES_MIN',basename)]
    local KEYBYTES_MAX = constants[string_format('%s_KEYBYTES_MAX',basename)]

    local BYTES = constants[string_format('%s_KEYBYTES',basename)]
    local BYTES_MIN = constants[string_format('%s_KEYBYTES_MIN',basename)]
    local BYTES_MAX = constants[string_format('%s_KEYBYTES_MAX',basename)]

    local STATEBYTES = sodium_lib[string_format('%s_statebytes',basename)]()

    local ls_crypto_generichash_free = function(state)
      sodium_lib.sodium_memzero(state,STATEBYTES)
      clib.free(state)
    end

    local ls_crypto_generichash_methods = {}
    local ls_crypto_generichash_mt = {
      __index = ls_crypto_generichash_methods
    }

    local M = {
      [crypto_generichash_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib[crypto_generichash_keygen](k)
        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,

      [crypto_generichash] = function(message, key, outlen)
        local out
        local keylen = 0

        if not message then
          return error('requires at least 1 parameter')
        end

        if key then
          keylen = string_len(key)
          if keylen < KEYBYTES_MIN then
            return error(string_format(
              'key too small, required minimum: %d', KEYBYTES_MIN))
          elseif keylen > KEYBYTES_MAX then
            return error(string_format(
              'key too large, required maximum: %d', KEYBYTES_MAX))
          end
        end

        if outlen then
          if outlen < BYTES_MIN then
            return error(string_format(
              'hash too small, required minimum: %d', BYTES_MIN))
          elseif outlen > BYTES_MAX then
            return error(string_format(
              'hash too large, required maximum: %d', BYTES_MAX))
          end
        else
          outlen = BYTES
        end

        out = char_array(outlen)

        if tonumber(sodium_lib[crypto_generichash](
          out,outlen,message,string_len(message),key,keylen)) == -1 then
          return error(string_format('%s error',crypto_generichash))
        end

        local out_str = ffi_string(out,outlen)
        sodium_lib.sodium_memzero(out,outlen)
        return out_str
      end,

      [crypto_generichash_init] = function(key, outlen)
        local keylen = 0
        if key then
          keylen = string_len(key)
          if keylen < KEYBYTES_MIN then
            return error(string_format(
              'key too small, required minimum: %d', KEYBYTES_MIN))
          elseif keylen > KEYBYTES_MAX then
            return error(string_format(
              'key too large, required maximum: %d', KEYBYTES_MAX))
          end
        end

        if outlen then
          if outlen < BYTES_MIN then
            return error(string_format(
              'hash too small, required minimum: %d', BYTES_MIN))
          elseif outlen > BYTES_MAX then
            return error(string_format(
              'hash too large, required maximum: %d', BYTES_MAX))
          end
        else
          outlen = BYTES
        end

        local state = ffi.gc(clib.malloc(STATEBYTES),ls_crypto_generichash_free)

        if tonumber(sodium_lib[crypto_generichash_init](state,key,keylen,outlen)) == -1 then
          return error(string_format('%s error',crypto_generichash_init))
        end

        return setmetatable({
          state = state,
          outlen = outlen,
        }, ls_crypto_generichash_mt)
      end,

      [crypto_generichash_update] = function(ls_state, message)
        if not message then
          return error('requires 2 parameters')
        end

        if getmetatable(ls_state) ~= ls_crypto_generichash_mt then
          return error('invalid userdata')
        end

        local mlen = string_len(message)

        return tonumber(sodium_lib[crypto_generichash_update](
          ls_state.state, message, mlen)) == 0
      end,

      [crypto_generichash_final] = function(ls_state, outlen)
        if not ls_state then
          return error('requires 1 parameter')
        end

        if getmetatable(ls_state) ~= ls_crypto_generichash_mt then
          return error('invalid userdata')
        end

        if not outlen then
          outlen = ls_state.outlen
        end

        local out = char_array(outlen)

        if tonumber(sodium_lib[crypto_generichash_final](ls_state.state,
          out,outlen)) == -1 then
          return error(string_format('%s error',crypto_generichash_final))
        end

        local out_str = ffi_string(out,outlen)
        sodium_lib.sodium_memzero(out,outlen)
        return out_str
      end,
    }

    ls_crypto_generichash_methods.update = M[crypto_generichash_update]
    ls_crypto_generichash_methods.final = M[crypto_generichash_final]

    return M
  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_generichash',
  }) do
    local m = ls_crypto_generichash(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end

