return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium
  local clib = libs.C

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_onetimeauth(basename)
    local crypto_onetimeauth = string_format('%s',basename)
    local crypto_onetimeauth_verify = string_format('%s_verify',basename)
    local crypto_onetimeauth_keygen = string_format('%s_keygen',basename)
    local crypto_onetimeauth_init = string_format('%s_init',basename)
    local crypto_onetimeauth_update = string_format('%s_update',basename)
    local crypto_onetimeauth_final = string_format('%s_final',basename)
    local BYTES = constants[string_format('%s_BYTES',basename)]
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local STATEBYTES = tonumber(sodium_lib[string_format('%s_statebytes',basename)]())

    local ls_crypto_onetimeauth_free = function(state)
      sodium_lib.sodium_memzero(state,STATEBYTES)
      clib.free(state)
    end

    local ls_crypto_onetimeauth_methods = {}
    local ls_crypto_onetimeauth_mt = {
      __index = ls_crypto_onetimeauth_methods
    }

    local M = {
      [crypto_onetimeauth] = function(message, key)
        if not key then
          return error('requires 2 arguments')
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
            'wrong key size, expected: %d',
            KEYBYTES))
        end

        local auth = char_array(BYTES)
        if tonumber(sodium_lib[crypto_onetimeauth](
            auth,message,string_len(message),key)) == -1 then
            return error(string_format('%s error', crypto_onetimeauth))
        end

        local auth_str = ffi_string(auth,BYTES)
        sodium_lib.sodium_memzero(auth,BYTES)
        return auth_str
      end,

      [crypto_onetimeauth_verify] = function(auth,message,key)
        if not key then
          return error('requires 3 arguments')
        end

        if string_len(auth) ~= BYTES then
          return error(string_format(
            'wrong auth size, expected: %d',
            BYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
            'wrong key size, expected: %d',
            KEYBYTES))
        end

        return tonumber(sodium_lib[crypto_onetimeauth_verify](
            auth,message,string_len(message),key)) ~= -1
      end,

      [crypto_onetimeauth_keygen] = function()
        local key = char_array(KEYBYTES)
        sodium_lib[crypto_onetimeauth_keygen](key)
        local key_str = ffi_string(key,KEYBYTES)
        sodium_lib.sodium_memzero(key,KEYBYTES)
        return key_str
      end,

      [crypto_onetimeauth_init] = function(key)
        if not key then
          return error('requires 1 parameter')
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
            'wrong key size, expected: %d',
            KEYBYTES
          ))
        end

        local state = ffi.gc(clib.malloc(STATEBYTES),ls_crypto_onetimeauth_free)
        if tonumber(sodium_lib[crypto_onetimeauth_init](state,key)) == -1 then
          return error(string_format('%s error',crypto_onetimeauth_init))
        end
        return setmetatable({
          state = state
        }, ls_crypto_onetimeauth_mt)
      end,

      [crypto_onetimeauth_update] = function(ls_state,m)
        if not m then
          return error('requires 2 parameters')
        end

        local mt = getmetatable(ls_state)
        if mt ~= ls_crypto_onetimeauth_mt then
          return error('invalid userdata')
        end

        return tonumber(sodium_lib[crypto_onetimeauth_update](
          ls_state.state,m,string_len(m))) ~= -1
      end,

      [crypto_onetimeauth_final] = function(ls_state)
        if not ls_state then
          return error('requires 1 parameter')
        end

        local mt = getmetatable(ls_state)
        if mt ~= ls_crypto_onetimeauth_mt then
          return error('invalid userdata')
        end

        local auth = char_array(BYTES)
        if tonumber(sodium_lib[crypto_onetimeauth_final](
          ls_state.state,auth)) == -1 then
          return error(string_format('%s error',crypto_onetimeauth_final))
        end

        local auth_str = ffi_string(auth,BYTES)
        sodium_lib.sodium_memzero(auth,BYTES)
        return auth_str
      end
    }
    ls_crypto_onetimeauth_methods.update = M[crypto_onetimeauth_update]
    ls_crypto_onetimeauth_methods.final = M[crypto_onetimeauth_final]

    return M
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_onetimeauth',
    'crypto_onetimeauth_poly1305',
  }) do
    local m = ls_crypto_onetimeauth(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end


