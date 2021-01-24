return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium
  local clib = libs.C

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_hash(basename)
    local crypto_hash = string_format('%s',basename)
    local BYTES = constants[string_format('%s_BYTES',basename)]

    return {
      [crypto_hash] = function(message)
        if not message then
          return error('requires 1 arguments')
        end

        local hash = char_array(BYTES)
        if tonumber(sodium_lib[crypto_hash](
            hash,message,string_len(message))) == -1 then
          return error(string_format('%s error',crypto_hash))
        end

        local hash_str = ffi_string(hash,BYTES)
        sodium_lib.sodium_memzero(hash,BYTES)
        return hash_str
      end,
    }
  end

  local function ls_crypto_hash_state(basename)
    local crypto_hash_init = string_format('%s_init',basename)
    local crypto_hash_update = string_format('%s_update',basename)
    local crypto_hash_final = string_format('%s_final',basename)
    local BYTES = constants[string_format('%s_BYTES',basename)]
    local STATEBYTES = tonumber(sodium_lib[string_format('%s_statebytes',basename)]())

    local ls_crypto_hash_free = function(state)
      sodium_lib.sodium_memzero(state,STATEBYTES)
      clib.free(state)
    end

    local ls_crypto_hash_methods = {}
    local ls_crypto_hash_mt = {
      __index = ls_crypto_hash_methods
    }

    local M = {
      [crypto_hash_init] = function()
        local state = ffi.gc(clib.malloc(STATEBYTES),ls_crypto_hash_free)
        if tonumber(sodium_lib[crypto_hash_init](state)) == -1 then
          return error(string_format('%s error',crypto_hash_init))
        end
        return setmetatable({
          state = state,
        }, ls_crypto_hash_mt)
      end,

      [crypto_hash_update] = function(ls_state,m)
        if not m then
          return error('requires 2 parameters')
        end

        local mt = getmetatable(ls_state)
        if mt ~= ls_crypto_hash_mt then
          return error('invalid userdata')
        end

        return tonumber(sodium_lib[crypto_hash_update](
          ls_state.state,m,string_len(m))) ~= -1
      end,

      [crypto_hash_final] = function(ls_state)
        if not ls_state then
          return error('requires 1 parameter')
        end

        local mt = getmetatable(ls_state)
        if mt ~= ls_crypto_hash_mt then
          return error('invalid userdata')
        end

        local h = char_array(BYTES)
        if tonumber(sodium_lib[crypto_hash_final](
          ls_state.state,h)) == -1 then
          return error(string_format('%s error',crypto_hash_final))
        end

        local h_str = ffi_string(h,BYTES)
        sodium_lib.sodium_memzero(h,BYTES)
        return h_str
      end,
    }

    ls_crypto_hash_methods.update = M[crypto_hash_update]
    ls_crypto_hash_methods.final = M[crypto_hash_final]

    return M
  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_hash',
    'crypto_hash_sha256',
    'crypto_hash_sha512',
  }) do
    local m = ls_crypto_hash(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for _,basename in ipairs({
    'crypto_hash_sha256',
    'crypto_hash_sha512',
  }) do
    local m = ls_crypto_hash_state(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
