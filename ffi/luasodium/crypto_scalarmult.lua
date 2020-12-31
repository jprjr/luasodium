local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string
local type = type

local char_array = ffi.typeof('char[?]')

local sodium_lib
local constants

local constant_keys = {
  'crypto_scalarmult_SCALARBYTES',
  'crypto_scalarmult_BYTES',
}

local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],
  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],
  ['crypto_scalarmult_base'] = [[
    int %s(unsigned char *q, const unsigned char *n)
  ]],
  ['crypto_scalarmult'] = [[
    int %s(unsigned char *q, const unsigned char *n,
           const unsigned char *p)
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
    sodium_lib[k] = ffi.cast(string_format(signatures[k],'(*)'),f)
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

local function lua_crypto_scalarmult_base(n)
  local q
  if not n then
    return error('requires 1 argument')
  end

  if(string_len(n) ~= constants.crypto_scalarmult_SCALARBYTES) then
    return error(string_format(
      'wrong scalar length, expected: %d',
      constants.crypto_scalarmult_SCALARBYTES
    ))
  end
  q = char_array(constants.crypto_scalarmult_BYTES)
  if sodium_lib.crypto_scalarmult_base(q,n) == -1 then
    return error('crypto_scalarmult_base error')
  end
  local q_str = ffi_string(q,constants.crypto_scalarmult_BYTES)
  sodium_lib.sodium_memzero(q,constants.crypto_scalarmult_BYTES)
  return q_str
end

local function lua_crypto_scalarmult(n,p)
  local q
  if not p then
    return error('requires 2 arguments')
  end

  if(string_len(n) ~= constants.crypto_scalarmult_SCALARBYTES) then
    return error(string.format(
      'wrong scalar length, expected: %d',
      constants.crypto_scalarmult_SCALARBYTES
    ))
  end

  if(string_len(p) ~= constants.crypto_scalarmult_BYTES) then
    return error(string_format(
      'wrong scalar length, expected: %d',
      constants.crypto_scalarmult_BYTES
    ))
  end

  q = char_array(constants.crypto_scalarmult_BYTES)
  if sodium_lib.crypto_scalarmult(q,n,p) == -1 then
    return error('crypto_scalarmult error')
  end
  local q_str = ffi_string(q,constants.crypto_scalarmult_BYTES)
  sodium_lib.sodium_memzero(q,constants.crypto_scalarmult_BYTES)
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
