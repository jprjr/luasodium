return function(sodium_lib, constants)

  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_scalarmult(basename)
    local crypto_scalarmult = string_format('%s',basename)
    local crypto_scalarmult_base = string_format('%s_base',basename)
    local BYTES = constants[string_format('%s_BYTES',basename)]
    local SCALARBYTES = constants[string_format('%s_SCALARBYTES',basename)]

    return {
      [crypto_scalarmult] = function(n,p)
        local q
        if not p then
          return error('requires 2 arguments')
        end

        if(string_len(n) ~= SCALARBYTES) then
          return error(string.format(
            'wrong scalar length, expected: %d',
            SCALARBYTES
          ))
        end

        if(string_len(p) ~= BYTES) then
          return error(string_format(
            'wrong scalar length, expected: %d',
            BYTES
          ))
        end

        q = char_array(BYTES)
        if sodium_lib[crypto_scalarmult](q,n,p) == -1 then
          return nil, string_format('%s error',crypto_scalarmult)
        end
        local q_str = ffi_string(q,BYTES)
        sodium_lib.sodium_memzero(q,BYTES)
        return q_str

      end,

      [crypto_scalarmult_base] = function(n)
        local q
        if not n then
          return error('requires 1 argument')
        end

        if(string_len(n) ~= SCALARBYTES) then
          return error(string_format(
            'wrong scalar length, expected: %d',
            SCALARBYTES
          ))
        end
        q = char_array(BYTES)
        if sodium_lib[crypto_scalarmult_base](q,n) == -1 then
          return nil, string_format('%s error',crypto_scalarmult_base)
        end
        local q_str = ffi_string(q,BYTES)
        sodium_lib.sodium_memzero(q,BYTES)
        return q_str
      end,
    }
  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_scalarmult',
    'crypto_scalarmult_curve25519',
  }) do
    local m = ls_crypto_scalarmult(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
