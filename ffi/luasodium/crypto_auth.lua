local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string
local type = type

local char_array = ffi.typeof('char[?]')

local constants
local sodium_lib

local constant_keys = {
  'crypto_auth_BYTES',
  'crypto_auth_KEYBYTES',
}

local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],
  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],
  ['crypto_auth'] = [[
    int %s(unsigned char *out, const unsigned char *in,
           unsigned long long inlen, const unsigned char *k)
  ]],
  ['crypto_auth_verify'] = [[
    int %s(const unsigned char *h, const unsigned char *in,
           unsigned long long inlen, const unsigned char *k)
  ]],
  ['crypto_auth_keygen'] = [[
    void %s(unsigned char *k)
  ]],
}

local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

local c_pointers = { ... }

if #c_pointers == 2 and
  type(c_pointers[1]) == 'table' then
  sodium_lib = {}

  for k,f in pairs(c_pointers[1]) do
    if signatures[k] then
      sodium_lib[k] = ffi.cast(string_format(signatures[k],'(*)'),f)
    end
  end

  constants = c_pointers[2]

else
  ffi.cdef([[
    int sodium_init(void);
  ]])
  do
    local ok, lib = pcall(test_cspace)
    if ok then
      sodium_lib = lib
    else
      sodium_lib = ffi.load('sodium')
    end
  end

  constants = {}

  for _,c in ipairs(constant_keys) do
    ffi.cdef('size_t ' .. c:lower() .. '(void);')
    constants[c] = tonumber(sodium_lib[c:lower()]())
  end

  for f,sig in pairs(signatures) do
    ffi.cdef(string_format(sig,f))
  end
end

local crypto_auth_BYTES = constants.crypto_auth_BYTES
local crypto_auth_KEYBYTES = constants.crypto_auth_KEYBYTES

local function ls_crypto_auth(message,key)
  if not key then
    return error('requires 2 arguments')
  end

  if string_len(key) ~= crypto_auth_KEYBYTES then
    return error('wrong key length, expected %d', crypto_auth_KEYBYTES)
  end

  local out = char_array(crypto_auth_BYTES)
  if tonumber(sodium_lib.crypto_auth(
    out,message,string_len(message),key)) == -1 then
    return error('crypto_auth error')
  end

  local out_str = ffi_string(out,crypto_auth_BYTES)
  sodium_lib.sodium_memzero(out,crypto_auth_BYTES)
  return out_str

end

local function ls_crypto_auth_verify(tag,message,key)
  if not key then
    return error('requires 3 arguments')
  end

  if string_len(key) ~= crypto_auth_KEYBYTES then
    return error('wrong key length, expected %d', crypto_auth_KEYBYTES)
  end

  return tonumber(sodium_lib.crypto_auth_verify(
    tag, message, string_len(message), key)) == 0
end

local function ls_crypto_auth_keygen()
  local k = char_array(crypto_auth_KEYBYTES)
  sodium_lib.crypto_auth_keygen(k)
  local k_str = ffi_string(k,crypto_auth_KEYBYTES)
  sodium_lib.sodium_memzero(k,crypto_auth_KEYBYTES)
  return k_str
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {
  crypto_auth = ls_crypto_auth,
  crypto_auth_verify = ls_crypto_auth_verify,
  crypto_auth_keygen = ls_crypto_auth_keygen,
}

for k,v in pairs(constants) do
  M[k] = v
end

return M
