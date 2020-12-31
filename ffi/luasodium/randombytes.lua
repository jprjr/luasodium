local ffi = require'ffi'
local string_len = string.len
local tonumber = tonumber
local ffi_string = ffi.string
local string_format = string.format
local type = type

local char_array = ffi.typeof('char[?]')

local constants
local sodium_lib

local constant_keys = {
  'randombytes_SEEDBYTES'
}

local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],
  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],
  ['randombytes_random'] = [[
    uint32_t %s(void)
  ]],
  ['randombytes_uniform'] = [[
    uint32_t %s(const uint32_t upper_bound)
  ]],
  ['randombytes_buf'] = [[
    void %s(void * const buf, const size_t size)
  ]],
  ['randombytes_buf_deterministic'] = [[
    void %s(void * const buf, const size_t size,
            const unsigned char *seed)
  ]],
  ['randombytes_close'] = [[
    int %s(void)
  ]],
  ['randombytes_stir'] = [[
    void %s(void)
  ]],
}

local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

-- function pointers are passed in from c module
local c_pointers = {...}

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

local function lua_randombytes_random()
  return tonumber(sodium_lib.randombytes_random())
end

local function lua_randombytes_uniform(upper)
  if(type(upper) ~= 'number') then
    return error('missing number argument')
  end
  return tonumber(sodium_lib.randombytes_uniform(upper))
end

local function lua_randombytes_buf(size)
  if(type(size) ~= 'number') then
    return error('missing number argument')
  end
  local tmp = char_array(size)
  sodium_lib.randombytes_buf(tmp,size)
  local tmp_str = ffi_string(tmp,size)
  sodium_lib.sodium_memzero(tmp,size)
  return tmp_str
end

local function lua_randombytes_buf_deterministic(size,seed)
  if not seed then
    return error('requires 2 arguments')
  end
  if string_len(seed) ~= constants.randombytes_SEEDBYTES then
    return error('wrong seed length')
  end
  local tmp = char_array(size)
  sodium_lib.randombytes_buf_deterministic(tmp,size,seed)
  local tmp_str = ffi_string(tmp,size)
  sodium_lib.sodium_memzero(tmp,size)
  return tmp_str
end

local function lua_randombytes_close()
  return sodium_lib.randombytes_close() == 0
end

local function lua_randombytes_stir()
  sodium_lib.randombytes_stir()
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {
  randombytes_random  = lua_randombytes_random,
  randombytes_uniform = lua_randombytes_uniform,
  randombytes_buf     = lua_randombytes_buf,
  randombytes_buf_deterministic = lua_randombytes_buf_deterministic,
  randombytes_close = lua_randombytes_close,
  randombytes_stir = lua_randombytes_stir,
}

for k,v in pairs(constants) do
  M[k] = v
end

return M
