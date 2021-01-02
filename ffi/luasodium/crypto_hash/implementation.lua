return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  local crypto_hash_BYTES = constants.crypto_hash_BYTES
  local crypto_hash_sha256_BYTES = constants.crypto_hash_sha256_BYTES
  local crypto_hash_sha512_BYTES = constants.crypto_hash_sha512_BYTES

  local function ls_crypto_hash(message)
    if not message then
      return error('requires 2 arguments')
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

  local M = {
    crypto_hash = ls_crypto_hash,
    crypto_hash_sha256 = ls_crypto_hash_sha256,
    crypto_hash_sha512 = ls_crypto_hash_sha512,
  }

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
