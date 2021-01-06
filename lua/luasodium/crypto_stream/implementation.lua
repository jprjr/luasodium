return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  local crypto_stream_KEYBYTES = constants.crypto_stream_KEYBYTES
  local crypto_stream_NONCEBYTES = constants.crypto_stream_NONCEBYTES

  local function ls_crypto_stream(size,nonce,key)
    if not key then
      return error('requires 3 parameters')
    end

    if string_len(nonce) ~= crypto_stream_NONCEBYTES then
      return error(string_format(
        'wrong nonce size, expected: %d',
        crypto_stream_NONCEBYTES))
    end

    if string_len(key) ~= crypto_stream_KEYBYTES then
      return error(string_format(
        'wrong nonce size, expected: %d',
        crypto_stream_KEYBYTES))
    end

    local c = char_array(size)

    if tonumber(sodium_lib.crypto_stream(c,size,nonce,key)) == -1 then
      return error('crypto_stream error')
    end

    local c_str = ffi_string(c,size)
    sodium_lib.sodium_memzero(c,size)
    return c_str
  end

  local function ls_crypto_stream_xor(message,nonce,key)
    if not key then
      return error('requires 3 parameters')
    end

    if string_len(nonce) ~= crypto_stream_NONCEBYTES then
      return error(string_format(
        'wrong nonce size, expected: %d',
        crypto_stream_NONCEBYTES))
    end

    if string_len(key) ~= crypto_stream_KEYBYTES then
      return error(string_format(
        'wrong nonce size, expected: %d',
        crypto_stream_KEYBYTES))
    end

    local mlen = string_len(message)

    local c = char_array(mlen)

    if tonumber(sodium_lib.crypto_stream_xor(c,message,mlen,nonce,key)) == -1 then
      return error('crypto_stream_xor error')
    end

    local c_str = ffi_string(c,mlen)
    sodium_lib.sodium_memzero(c,mlen)
    return c_str
  end

  local function ls_crypto_stream_keygen()
    local k = char_array(crypto_stream_KEYBYTES)
    sodium_lib.crypto_stream_keygen(k)
    local k_str = ffi_string(k,crypto_stream_KEYBYTES)
    sodium_lib.sodium_memzero(k,crypto_stream_KEYBYTES)
    return k_str
  end

  local M = {
    crypto_stream = ls_crypto_stream,
    crypto_stream_xor = ls_crypto_stream_xor,
    crypto_stream_keygen = ls_crypto_stream_keygen,
  }

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end

