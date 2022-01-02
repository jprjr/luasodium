return function(sodium_lib, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_stream(basename)
    local crypto_stream = string_format('%s',basename)
    local crypto_stream_xor = string_format('%s_xor',basename)
    local crypto_stream_keygen = string_format('%s_keygen',basename)

    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local NONCEBYTES = constants[string_format('%s_NONCEBYTES',basename)]

    return {

      [crypto_stream] = function(size,nonce,key)
        if not key then
          return error('requires 3 parameters')
        end

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
            'wrong nonce size, expected: %d',
            KEYBYTES))
        end

        local c = char_array(size)

        if tonumber(sodium_lib[crypto_stream](c,size,nonce,key)) == -1 then
          return nil, string_format('%s error', crypto_stream)
        end

        local c_str = ffi_string(c,size)
        sodium_lib.sodium_memzero(c,size)
        return c_str
      end,

      [crypto_stream_xor] = function(message,nonce,key)
        if not key then
          return error('requires 3 parameters')
        end

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
            'wrong nonce size, expected: %d',
            KEYBYTES))
        end

        local mlen = string_len(message)

        local c = char_array(mlen)

        if tonumber(sodium_lib[crypto_stream_xor](c,message,mlen,nonce,key)) == -1 then
          return nil, string_format('%s error',crypto_stream_xor)
        end

        local c_str = ffi_string(c,mlen)
        sodium_lib.sodium_memzero(c,mlen)
        return c_str

      end,

      [crypto_stream_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib[crypto_stream_keygen](k)
        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,
    }
  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_stream',
    'crypto_stream_xsalsa20',
    'crypto_stream_salsa20',
    'crypto_stream_salsa2012',
  }) do
    local m = ls_crypto_stream(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end

