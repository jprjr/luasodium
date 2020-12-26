local ffi = require'ffi'
local string_len = string.len
local tonumber = tonumber

local sodium_lib

-- https://libsodium.gitbook.io/doc/generating_random_data
ffi.cdef [[
uint32_t randombytes_random(void);
uint32_t randombytes_uniform(const uint32_t upper_bound);
void randombytes_buf(const * const buf, const size_t size);
size_t randombytes_seedbytes(void);
int randombytes_close(void);
void randombytes_stir(void);
]]

local function test_cspace()
  if ffi.C.randombytes_random then
    return ffi.C
  end
end

do
  local ok, lib = pcall(test_cspace)
  if ok then
    sodium_lib = lib
  else
    sodium_lib = ffi.load('sodium')
  end
end

local SEEDBYTES = tonumber(sodium_lib.randombytes_seedbytes())

ffi.cdef([[
void randombytes_buf_deterministic(void * const buf, const size_t size,
                                   const unsigned char seed[]]
.. SEEDBYTES .. [[]);]])

local function randombytes_random()
  return tonumber(sodium_lib.randombytes_random())
end

local function randombytes_uniform(upper)
  return tonumber(sodium_lib.randombytes_uniform(upper))
end

local function randombytes_buf(size)
  local tmp = ffi.new('char[?]',size)
  sodium_lib.randombytes_buf(tmp,size)
  return ffi.string(tmp,size)
end

local function randombytes_seedbytes()
  return tonumber(sodium_lib.randombytes_seedbytes())
end

local function randombytes_buf_deterministic(size, seed)
  if string_len(seed) ~= SEEDBYTES then
    return nil,'wrong seed length'
  end
  local tmp = ffi.new('char[?]',size)
  sodium_lib.randombytes_buf_deterministic(tmp,size,seed)
  return ffi.string(tmp,size)
end

local function randombytes_close()
  return sodium_lib.randombytes_close() == 0
end

local function randombytes_stir()
  sodium_lib.randombytes_stir()
end

local M = {
  random = randombytes_random,
  uniform = randombytes_uniform,
  buf = randombytes_buf,
  buf_deterministic = randombytes_buf_deterministic,
  close = randombytes_close,
  stir = randombytes_stir,
  seedbytes = randombytes_seedbytes,
  SEEDBYTES = SEEDBYTES,
}

return M
