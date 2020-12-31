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
  {
    functions = { 'randombytes_random' },
    signature = [[
      uint32_t %s(void);
    ]],
  },
  {
    functions = { 'randombytes_uniform' },
    signature = [[
      uint32_t %s(const uint32_t upper_bound);
    ]],
  },
  {
    functions = { 'randombytes_buf' },
    signature = [[
      void %s(void * const buf, const size_t size);
    ]],
  },
  {
    functions = { 'randombytes_buf_deterministic' },
    signature = [[
      void %s(void * const buf, const size_t size,
               const unsigned char *seed);
    ]],
  },
  {
    functions = { 'randombytes_close' },
    signature = [[
      int %s(void);
    ]],
  },
  {
    functions = { 'randombytes_stir' },
    signature = [[
      void %s(void);
    ]],
  }
}

local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

-- function pointers are passed in from c module
local c_pointers = {...}

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

local function lua_randombytes_random(fname)
  return function()
    return tonumber(sodium_lib[fname]())
  end
end

local function lua_randombytes_uniform(fname)
  return function(upper)
    if(type(upper) ~= 'number') then
      return error('missing number argument')
    end
    return tonumber(sodium_lib[fname](upper))
  end
end

local function lua_randombytes_buf(fname)
  return function(size)
    if(type(size) ~= 'number') then
      return error('missing number argument')
    end
    local tmp = char_array(size)
    sodium_lib[fname](tmp,size)
    local tmp_str = ffi_string(tmp,size)
    sodium_lib.sodium_memzero(tmp,size)
    return tmp_str
  end
end

local function lua_randombytes_buf_deterministic(fname,seedbytes)
  return function(size,seed)
    if not seed then
      return error('requires 2 arguments')
    end
    if string_len(seed) ~= seedbytes then
      return error('wrong seed length')
    end
    local tmp = char_array(size)
    sodium_lib[fname](tmp,size,seed)
    local tmp_str = ffi_string(tmp,size)
    sodium_lib.sodium_memzero(tmp,size)
    return tmp_str
  end
end

local function lua_randombytes_close(fname)
  return function()
    return sodium_lib[fname]() == 0
  end
end

local function lua_randombytes_stir(fname)
  return function()
    sodium_lib[fname]()
  end
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {}

for k,v in pairs(constants) do
  M[k] = v
end

M.randombytes_random  = lua_randombytes_random('randombytes_random')
M.randombytes_uniform = lua_randombytes_uniform('randombytes_uniform')
M.randombytes_buf     = lua_randombytes_buf('randombytes_buf')
M.randombytes_buf_deterministic = lua_randombytes_buf_deterministic(
  'randombytes_buf_deterministic',
  constants.randombytes_SEEDBYTES)
M.randombytes_close = lua_randombytes_close('randombytes_close')
M.randombytes_stir = lua_randombytes_stir('randombytes_stir')

return M
