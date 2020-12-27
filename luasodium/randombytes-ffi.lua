local ffi = require'ffi'
local string_len = string.len
local tonumber = tonumber
local ffi_string = ffi.string

local char_array = ffi.typeof('char[?]')

-- function pointers are passed in from c module
local c_pointers = {...}

-- https://libsodium.gitbook.io/doc/generating_random_data
ffi.cdef [[
uint32_t randombytes_random(void);
uint32_t randombytes_uniform(const uint32_t upper_bound);
void randombytes_buf(const * const buf, const size_t size);
size_t randombytes_seedbytes(void);
int randombytes_close(void);
void randombytes_stir(void);
]]

local randombytes_SEEDBYTES = c_pointers[1]

local randombytes_random = ffi.cast([[
uint32_t (*)(void)
]],c_pointers[2])

local randombytes_uniform = ffi.cast([[
uint32_t (*)(const uint32_t)
]],c_pointers[3])

local randombytes_buf = ffi.cast([[
void (*)(const * const, const size_t)
]],c_pointers[4])

local randombytes_seedbytes = ffi.cast([[
size_t (*)(void)
]],c_pointers[5])

local randombytes_close = ffi.cast([[
int (*)(void)
]],c_pointers[6])

local randombytes_stir = ffi.cast([[
void (*)(void)
]],c_pointers[7])

local randombytes_buf_deterministic = ffi.cast([[
void (*)(void * const, const size_t, const unsigned char[ ]]
.. randombytes_SEEDBYTES .. [[ ])]],c_pointers[8])

local function lua_randombytes_random()
  return tonumber(randombytes_random())
end

local function lua_randombytes_uniform(upper)
  if(type(upper) ~= 'number') then
    return error('missing number argument')
  end
  return tonumber(randombytes_uniform(upper))
end

local function lua_randombytes_buf(size)
  if(type(upper) ~= 'number') then
    return error('missing number argument')
  end
  local tmp = char_array(size)
  randombytes_buf(tmp,size)
  return ffi.string(tmp,size)
end

local function lua_randombytes_seedbytes()
  return tonumber(randombytes_seedbytes())
end

local function lua_randombytes_buf_deterministic(size, seed)
  if not seed then
    return error('requires 2 arguments')
  end
  if string_len(seed) ~= randombytes_SEEDBYTES then
    return error('wrong seed length')
  end
  local tmp = char_array(size)
  randombytes_buf_deterministic(tmp,size,seed)
  return ffi.string(tmp,size)
end

local function lua_randombytes_close()
  return randombytes_close() == 0
end

local function lua_randombytes_stir()
  randombytes_stir()
end

local M = {
  random = lua_randombytes_random,
  uniform = lua_randombytes_uniform,
  buf = lua_randombytes_buf,
  buf_deterministic = lua_randombytes_buf_deterministic,
  close = lua_randombytes_close,
  stir = lua_randombytes_stir,
  seedbytes = lua_randombytes_seedbytes,
  SEEDBYTES = randombytes_SEEDBYTES,
}

return M
