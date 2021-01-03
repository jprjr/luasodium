return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local ffi_string = ffi.string
  local istype = ffi.istype
  local tonumber = tonumber

  local sodium_lib = libs.sodium
  local clib = libs.C

  local char_array = ffi.typeof('char[?]')

  -- create struct wrappers for sha states
  ffi.cdef([[
  typedef struct { void *state; } ls_crypto_hash_sha256_state_t;
  typedef struct { void *state; } ls_crypto_hash_sha512_state_t;
  ]])

  local crypto_hash_BYTES = constants.crypto_hash_BYTES
  local crypto_hash_sha256_BYTES = constants.crypto_hash_sha256_BYTES
  local crypto_hash_sha512_BYTES = constants.crypto_hash_sha512_BYTES
  local crypto_hash_sha256_STATEBYTES = tonumber(sodium_lib.crypto_hash_sha256_statebytes())
  local crypto_hash_sha512_STATEBYTES = tonumber(sodium_lib.crypto_hash_sha512_statebytes())

  local function ls_sha256_free(state)
   sodium_lib.sodium_memzero(state,crypto_hash_sha256_STATEBYTES)
   clib.free(state)
  end

  local function ls_sha512_free(state)
   sodium_lib.sodium_memzero(state,crypto_hash_sha512_STATEBYTES)
   clib.free(state)
  end

  local ls_crypto_hash_sha256_methods = {}
  local ls_crypto_hash_sha512_methods = {}
  local ls_crypto_hash_sha256_mt = {
    __index = ls_crypto_hash_sha256_methods,
  }
  local ls_crypto_hash_sha512_mt = {
    __index = ls_crypto_hash_sha512_methods,
  }

  local ls_crypto_hash_sha256_state_t = ffi.metatype('ls_crypto_hash_sha256_state_t',ls_crypto_hash_sha256_mt)
  local ls_crypto_hash_sha512_state_t = ffi.metatype('ls_crypto_hash_sha512_state_t',ls_crypto_hash_sha512_mt)

  local function ls_crypto_hash(message)
    if not message then
      return error('requires 1 arguments')
    end

    local hash = char_array(crypto_hash_BYTES)
    if tonumber(sodium_lib.crypto_hash(
        hash,message,string_len(message))) == -1 then
      return error('crypto_hash error')
    end

    local hash_str = ffi_string(hash,crypto_hash_BYTES)
    sodium_lib.sodium_memzero(hash,crypto_hash_BYTES)
    return hash_str
  end

  local function ls_crypto_hash_sha256(message)
    if not message then
      return error('requires 2 arguments')
    end

    local hash = char_array(crypto_hash_sha256_BYTES)
    if tonumber(sodium_lib.crypto_hash_sha256(
        hash,message,string_len(message))) == -1 then
      return error('crypto_hash_sha256 error')
    end

    local hash_str = ffi_string(hash,crypto_hash_sha256_BYTES)
    sodium_lib.sodium_memzero(hash,crypto_hash_sha256_BYTES)
    return hash_str
  end

  local function ls_crypto_hash_sha512(message)
    if not message then
      return error('requires 2 arguments')
    end

    local hash = char_array(crypto_hash_sha512_BYTES)
    if tonumber(sodium_lib.crypto_hash_sha512(
        hash,message,string_len(message))) == -1 then
      return error('crypto_hash_sha512 error')
    end

    local hash_str = ffi_string(hash,crypto_hash_sha512_BYTES)
    sodium_lib.sodium_memzero(hash,crypto_hash_sha512_BYTES)
    return hash_str
  end

  local function ls_crypto_hash_sha256_init()
    local ls_state = ls_crypto_hash_sha256_state_t()
    ls_state.state = ffi.gc(clib.malloc(crypto_hash_sha256_STATEBYTES),ls_sha256_free)
    if tonumber(sodium_lib.crypto_hash_sha256_init(ls_state.state)) == -1 then
      return error('crypto_hash_sha256_init error')
    end
    return ls_state
  end

  local function ls_crypto_hash_sha256_update(ls_state,m)
    if not m then
      return error('requires 2 parameters')
    end

    if not istype(ls_crypto_hash_sha256_state_t,ls_state) then
      return error('invalid userdata')
    end

    return tonumber(sodium_lib.crypto_hash_sha256_update(
      ls_state.state,m,string_len(m))) ~= -1
  end

  local function ls_crypto_hash_sha256_final(ls_state)
    if not ls_state then
      return error('requires 1 parameter')
    end

    if not istype(ls_crypto_hash_sha256_state_t,ls_state) then
      return error('invalid userdata')
    end

    local h = char_array(crypto_hash_sha256_BYTES)
    if tonumber(sodium_lib.crypto_hash_sha256_final(
      ls_state.state,h)) == -1 then
      return error('crypto_hash_sha256_final error')
    end

    local h_str = ffi_string(h,crypto_hash_sha256_BYTES)
    sodium_lib.sodium_memzero(h,crypto_hash_sha256_BYTES)
    return h_str
  end

  local function ls_crypto_hash_sha512_init()
    local ls_state = ls_crypto_hash_sha512_state_t()
    ls_state.state = ffi.gc(clib.malloc(crypto_hash_sha512_STATEBYTES),ls_sha512_free)
    if tonumber(sodium_lib.crypto_hash_sha512_init(ls_state.state)) == -1 then
      return error('crypto_hash_sha512_init error')
    end
    return ls_state
  end

  local function ls_crypto_hash_sha512_update(ls_state,m)
    if not m then
      return error('requires 2 parameters')
    end

    if not istype(ls_crypto_hash_sha512_state_t,ls_state) then
      return error('invalid userdata')
    end

    return tonumber(sodium_lib.crypto_hash_sha512_update(
      ls_state.state,m,string_len(m))) ~= -1
  end

  local function ls_crypto_hash_sha512_final(ls_state)
    if not ls_state then
      return error('requires 1 parameter')
    end

    if not istype(ls_crypto_hash_sha512_state_t,ls_state) then
      return error('invalid userdata')
    end

    local h = char_array(crypto_hash_sha512_BYTES)
    if tonumber(sodium_lib.crypto_hash_sha512_final(
      ls_state.state,h)) == -1 then
      return error('crypto_hash_sha512_final error')
    end

    local h_str = ffi_string(h,crypto_hash_sha512_BYTES)
    sodium_lib.sodium_memzero(h,crypto_hash_sha512_BYTES)
    return h_str
  end

  ls_crypto_hash_sha256_methods.update = ls_crypto_hash_sha256_update
  ls_crypto_hash_sha256_methods.final = ls_crypto_hash_sha256_final
  ls_crypto_hash_sha512_methods.update = ls_crypto_hash_sha512_update
  ls_crypto_hash_sha512_methods.final = ls_crypto_hash_sha512_final

  local M = {
    crypto_hash = ls_crypto_hash,
    crypto_hash_sha256 = ls_crypto_hash_sha256,
    crypto_hash_sha512 = ls_crypto_hash_sha512,
    crypto_hash_sha256_init = ls_crypto_hash_sha256_init,
    crypto_hash_sha256_update = ls_crypto_hash_sha256_update,
    crypto_hash_sha256_final = ls_crypto_hash_sha256_final,
    crypto_hash_sha512_init = ls_crypto_hash_sha512_init,
    crypto_hash_sha512_update = ls_crypto_hash_sha512_update,
    crypto_hash_sha512_final = ls_crypto_hash_sha512_final,
  }

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
