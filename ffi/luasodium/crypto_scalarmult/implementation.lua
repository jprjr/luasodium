return function(libs, constants)

  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string

  local char_array = ffi.typeof('char[?]')

  local sodium_lib = libs.sodium

  local crypto_scalarmult_SCALARBYTES = constants.crypto_scalarmult_SCALARBYTES
  local crypto_scalarmult_BYTES       = constants.crypto_scalarmult_BYTES

  local function lua_crypto_scalarmult_base(n)
    local q
    if not n then
      return error('requires 1 argument')
    end

    if(string_len(n) ~= crypto_scalarmult_SCALARBYTES) then
      return error(string_format(
        'wrong scalar length, expected: %d',
        crypto_scalarmult_SCALARBYTES
      ))
    end
    q = char_array(crypto_scalarmult_BYTES)
    if sodium_lib.crypto_scalarmult_base(q,n) == -1 then
      return error('crypto_scalarmult_base error')
    end
    local q_str = ffi_string(q,crypto_scalarmult_BYTES)
    sodium_lib.sodium_memzero(q,crypto_scalarmult_BYTES)
    return q_str
  end

  local function lua_crypto_scalarmult(n,p)
    local q
    if not p then
      return error('requires 2 arguments')
    end

    if(string_len(n) ~= crypto_scalarmult_SCALARBYTES) then
      return error(string.format(
        'wrong scalar length, expected: %d',
        crypto_scalarmult_SCALARBYTES
      ))
    end

    if(string_len(p) ~= crypto_scalarmult_BYTES) then
      return error(string_format(
        'wrong scalar length, expected: %d',
        crypto_scalarmult_BYTES
      ))
    end

    q = char_array(crypto_scalarmult_BYTES)
    if sodium_lib.crypto_scalarmult(q,n,p) == -1 then
      return error('crypto_scalarmult error')
    end
    local q_str = ffi_string(q,crypto_scalarmult_BYTES)
    sodium_lib.sodium_memzero(q,crypto_scalarmult_BYTES)
    return q_str
  end

  if sodium_lib.sodium_init() == -1 then
    return error('sodium_init error')
  end

  local M = {
    crypto_scalarmult_base = lua_crypto_scalarmult_base,
    crypto_scalarmult = lua_crypto_scalarmult,
  }

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
