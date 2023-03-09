return function(sodium_lib, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local tonumber = tonumber
  local ffi_string = ffi.string
  local type = type

  local char_array = ffi.typeof('char[?]')

  local randombytes_SEEDBYTES = constants.randombytes_SEEDBYTES

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
    if string_len(seed) ~= randombytes_SEEDBYTES then
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

  if tonumber(sodium_lib.sodium_init()) == -1 then
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
end
