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
  {
    functions = {'crypto_scalarmult_base'},
    signature = [[
      int %s(unsigned char *q, const unsigned char *n)
    ]],
  },
  {
    functions = {'crypto_scalarmult'},
    signature = [[
      int %s(unsigned char *q, const unsigned char *n,
             const unsigned char *p)
    ]],
  }
}

local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

local c_pointers = { ... }
if #c_pointers == 3 and
  type(c_pointers[1]) == 'table' then
  sodium_lib = {}

  sodium_lib.sodium_init = ffi.cast(
    c_pointers[1].sodium_init.signature,
    c_pointers[1].sodium_init.func)

  sodium_lib.sodium_memzero = ffi.cast(
    c_pointers[1].sodium_memzero.signature,
    c_pointers[1].sodium_memzero.func)

  constants = c_pointers[2]

  for _,f in ipairs(c_pointers[3]) do
    sodium_lib[f.name] = ffi.cast(f.signature,f.func)
  end

else
  ffi.cdef([[
    int sodium_init(void);
    void sodium_memzero(void * const pnt, const size_t len);
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

  for _,v in ipairs(signatures) do
    for _,f in ipairs(v.functions) do
      ffi.cdef(string_format(v.signature,f))
    end
  end

end

local function lua_crypto_scalarmult_base(fname,scalarbytes,bytes)
  return function(n)
    local q
    if not n then
      return error('requires 1 argument')
    end

    if(string_len(n) ~= scalarbytes) then
      return error(string_format(
        'wrong scalar length, expected: %d',
        scalarbytes
      ))
    end
    q = char_array(bytes)
    if sodium_lib[fname](q,n) == -1 then
      return error(string_format('%s error',fname))
    end
    local q_str = ffi_string(q,bytes)
    sodium_lib.sodium_memzero(q,bytes)
    return q_str
  end
end

local function lua_crypto_scalarmult(fname,scalarbytes,bytes)
  return function(n,p)
    local q
    if not p then
      return error('requires 2 arguments')
    end

    if(string_len(n) ~= scalarbytes) then
      return error(string.format(
        'wrong scalar length, expected: %d',
        scalarbytes
      ))
    end

    if(string_len(p) ~= bytes) then
      return error(string_format(
        'wrong scalar length, expected: %d',
        bytes
      ))
    end

    q = char_array(bytes)
    if sodium_lib[fname](q,n,p) == -1 then
      return error('%s error',fname)
    end
    local q_str = ffi_string(q,bytes)
    sodium_lib.sodium_memzero(q,bytes)
    return q_str
  end
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end


local M = {}

for k,v in pairs(constants) do
  M[k] = v
end

M.crypto_scalarmult_base = lua_crypto_scalarmult_base(
  'crypto_scalarmult_base',
  constants.crypto_scalarmult_SCALARBYTES,
  constants.crypto_scalarmult_BYTES)

M.crypto_scalarmult = lua_crypto_scalarmult(
  'crypto_scalarmult',
  constants.crypto_scalarmult_SCALARBYTES,
  constants.crypto_scalarmult_BYTES)

return M
