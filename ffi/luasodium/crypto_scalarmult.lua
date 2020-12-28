local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string

local char_array = ffi.typeof('char[?]')

local sodium_lib
local crypto_scalarmult_BYTES
local crypto_scalarmult_SCALARBYTES

local function test_cspace()
  if ffi.C.crypto_scalarmult_base then
    return ffi.C
  end
end

local c_pointers = { ... }
if #c_pointers > 1 then
  sodium_lib = {}

  crypto_scalarmult_BYTES       = c_pointers[1]
  crypto_scalarmult_SCALARBYTES = c_pointers[2]

  sodium_lib.crypto_scalarmult_base = ffi.cast([[
    int (*)(unsigned char *, const unsigned char *)
  ]], c_pointers[3])

  sodium_lib.crypto_scalarmult = ffi.cast([[
    int (*)(unsigned char *, const unsigned char *, const unsigned char *)
  ]], c_pointers[4])
else
  ffi.cdef([[
    size_t crypto_scalarmult_bytes(void);
    size_t crypto_scalarmult_scalarbytes(void);
    int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
    int crypto_scalarmult(unsigned char *q, const unsigned char *n,
                          const unsigned char *p);
  ]])
  do
    local ok, lib = pcall(test_cspace)
    if ok then
      sodium_lib = lib
    else
      sodium_lib = ffi.load('sodium')
    end
  end

  crypto_scalarmult_BYTES = tonumber(sodium_lib.crypto_scalarmult_bytes())
  crypto_scalarmult_SCALARBYTES = tonumber(sodium_lib.crypto_scalarmult_scalarbytes())
end

local function lua_crypto_scalarmult_base(n)
  local q
  if not n then
    return error('requires 1 argument')
  end
  if(string_len(n) ~= crypto_scalarmult_SCALARBYTES) then
    return error(string.format(
      'wrong scalar length, expected: %d',
      crypto_scalarmult_SCALARBYTES
    ))
  end
  q = char_array(crypto_scalarmult_BYTES)
  if sodium_lib.crypto_scalarmult_base(q,n) == -1 then
    return error('crypto_scalarmult_base error')
  end
  return ffi_string(q,crypto_scalarmult_BYTES)
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
    return error(string.format(
      'wrong scalar length, expected: %d',
      crypto_scalarmult_BYTES
    ))
  end

  q = char_array(crypto_scalarmult_BYTES)
  if sodium_lib.crypto_scalarmult(q,n,p) == -1 then
    return error('crypto_scalarmult_base error')
  end
  return ffi_string(q,crypto_scalarmult_BYTES)
end

local M = {
  BYTES = crypto_scalarmult_BYTES,
  SCALARBYTES = crypto_scalarmult_SCALARBYTES,
  base = lua_crypto_scalarmult_base,
  scalarmult = lua_crypto_scalarmult,
}

return M
