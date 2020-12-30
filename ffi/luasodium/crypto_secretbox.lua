local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string
local type = type

local char_array = ffi.typeof('char[?]')

local sodium_lib
local constants

local constant_keys = {
  'crypto_secretbox_KEYBYTES',
  'crypto_secretbox_MACBYTES',
  'crypto_secretbox_NONCEBYTES',

  'crypto_secretbox_xsalsa20poly1305_KEYBYTES',
  'crypto_secretbox_xsalsa20poly1305_NONCEBYTES',
  'crypto_secretbox_xsalsa20poly1305_MACBYTES',

  'crypto_secretbox_xchacha20poly1305_KEYBYTES',
  'crypto_secretbox_xchacha20poly1305_NONCEBYTES',
  'crypto_secretbox_xchacha20poly1305_MACBYTES',

  'crypto_secretbox_ZEROBYTES',
  'crypto_secretbox_xsalsa20poly1305_ZEROBYTES',

  'crypto_secretbox_BOXZEROBYTES',
  'crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES',
}

local signatures = {
  {
    functions = {'crypto_secretbox_keygen',
                 'crypto_secretbox_xsalsa20poly1305_keygen' },
    signature = [[
      void %s(unsigned char *k)
    ]],
  },
  {
    functions = {'crypto_secretbox',
                 'crypto_secretbox_open',
                 'crypto_secretbox_easy',
                 'crypto_secretbox_open_easy',
                 'crypto_secretbox_xsalsa20poly1305',
                 'crypto_secretbox_xsalsa20poly1305_open',
                 'crypto_secretbox_xchacha20poly1305_easy',
                 'crypto_secretbox_xchacha20poly1305_open_easy'},
    signature = [[
      int %s(unsigned char *c,
              const unsigned char *m,
              unsigned long long mlen,
              const unsigned char *n,
              const unsigned char *k)
    ]],
  },
  {
    functions = {'crypto_secretbox_detached',
                 'crypto_secretbox_xchacha20poly1305_detached'},
    signature = [[
      int %s(unsigned char *c,
              unsigned char *mac,
              const unsigned char *m,
              unsigned long long mlen,
              const unsigned char *n,
              const unsigned char *k)
    ]],
  },
  {
    functions = {'crypto_secretbox_open_detached',
                 'crypto_secretbox_xchacha20poly1305_open_detached'},
    signature = [[
      int %s(unsigned char *m,
              const unsigned char *c,
              const unsigned char *mac,
              unsigned long long clen,
              const unsigned char *n,
              const unsigned char *k)
    ]],
  },
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

local function lua_crypto_secretbox(fname,noncesize,macsize,keysize,zerosize,boxzerosize)
  return function(input, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local inputlen = string_len(input)
    local outputlen = inputlen + macsize

    if string_len(nonce) ~= noncesize then
      return error(string_format('wrong nonce size, expected: %d',
        noncesize))
    end

    if string_len(key) ~= keysize then
      return error(string_format('wrong key size, expected: %d',
        keysize))
    end

    local tmp_input = char_array(inputlen + zerosize)
    ffi.fill(tmp_input,zerosize,0)
    ffi.copy(tmp_input+zerosize,input,inputlen)

    local output = char_array(outputlen + boxzerosize)
    ffi.fill(output,boxzerosize,0)

    if sodium_lib[fname](
      output,tmp_input,inputlen+zerosize,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end
    local output_str = ffi_string(output+boxzerosize,outputlen)
    sodium_lib.sodium_memzero(tmp_input,inputlen+zerosize)
    sodium_lib.sodium_memzero(output,outputlen+boxzerosize)
    return output_str
  end
end

local function lua_crypto_secretbox_open(fname,noncesize,macsize,keysize,zerosize,boxzerosize)
  return function(input, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local inputlen = string_len(input)

    if inputlen <= macsize then
      return error(string.format('wrong input size, expected at least: %d',
        macsize))
    end

    if string_len(nonce) ~= noncesize then
      return error(string_format('wrong nonce size, expected: %d',
        noncesize))
    end

    if string_len(key) ~= keysize then
      return error(string_format('wrong key size, expected: %d',
        keysize))
    end

    local outputlen = inputlen - macsize

    local tmp_input = char_array(inputlen + boxzerosize)
    ffi.fill(tmp_input,boxzerosize,0)
    ffi.copy(tmp_input+boxzerosize,input,inputlen)

    local output = char_array(outputlen + zerosize)
    ffi.fill(output,zerosize,0)

    if sodium_lib[fname](
      output,tmp_input,inputlen+boxzerosize,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end

    local output_str = ffi_string(output+zerosize,outputlen)
    sodium_lib.sodium_memzero(tmp_input,inputlen + boxzerosize)
    sodium_lib.sodium_memzero(output,outputlen + zerosize)
    return output_str
  end
end

local function lua_crypto_secretbox_easy(fname,noncesize,macsize,keysize)
  return function(input, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local inputlen = string_len(input)
    local outputlen = inputlen + macsize

    if string_len(nonce) ~= noncesize then
      return error(string_format('wrong nonce size, expected: %d',
        noncesize))
    end

    if string_len(key) ~= keysize then
      return error(string_format('wrong key size, expected: %d',
        keysize))
    end

    local output = char_array(outputlen)

    if sodium_lib[fname](
      output,input,inputlen,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end

    local output_str = ffi_string(output,outputlen)
    sodium_lib.sodium_memzero(output,outputlen)
    return output_str
  end
end

local function lua_crypto_secretbox_open_easy(fname,noncesize,macsize,keysize)
  return function(input, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local inputlen = string_len(input)

    if inputlen <= macsize then
      return error(string.format('wrong input size, expected at least: %d',
        macsize))
    end

    if string_len(nonce) ~= noncesize then
      return error(string_format('wrong nonce size, expected: %d',
        noncesize))
    end

    if string_len(key) ~= keysize then
      return error(string_format('wrong key size, expected: %d',
        keysize))
    end

    local outputlen = inputlen - macsize
    local output = char_array(outputlen)

    if sodium_lib[fname](
      output,input,inputlen,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end

    local output_str = ffi_string(output,outputlen)
    sodium_lib.sodium_memzero(output,outputlen)
    return output_str
  end
end

local function lua_crypto_secretbox_detached(fname, noncesize, macsize, keysize)
  return function(message,nonce,key)
    if not key then
      return error('requires 3 arguments')
    end

    local mlen = string_len(message)

    if string_len(nonce) ~= noncesize then
      return error(string_format('wrong nonce size, expected: %d',
        noncesize))
    end

    if string_len(key) ~= keysize then
      return error(string_format('wrong key size, expected: %d',
        keysize))
    end

    local c = char_array(mlen)
    local mac = char_array(macsize)

    if sodium_lib[fname](
      c,mac,message,mlen,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end
    local c_str = ffi_string(c,mlen)
    local mac_str = ffi_string(mac,macsize)
    sodium_lib.sodium_memzero(c,mlen)
    sodium_lib.sodium_memzero(mac,macsize)
    return c_str, mac_str
  end
end

local function lua_crypto_secretbox_open_detached(fname, noncesize, macsize, keysize)
  return function(cipher,mac,nonce,key)
    if not key then
      return error('requires 4 arguments')
    end

    local clen = string_len(cipher)

    if string_len(mac) ~= macsize then
      return error(string_format('wrong mac size, expected: %d',
        macsize))
    end

    if string_len(nonce) ~= noncesize then
      return error(string_format('wrong nonce size, expected: %d',
        noncesize))
    end

    if string_len(key) ~= keysize then
      return error(string_format('wrong key size, expected: %d',
        noncesize))
    end

    local m = char_array(clen)
    if sodium_lib[fname](
      m,cipher,mac,clen,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end

    local m_str = ffi_string(m,clen)
    sodium_lib.sodium_memzero(m,clen)
    return m_str
  end
end

local function lua_crypto_secretbox_keygen(fname,size)
  return function()
    local k = char_array(size)
    sodium_lib[fname](k)
    local k_str = ffi_string(k,size)
    sodium_lib.sodium_memzero(k,size)
    return k_str
  end
end

if sodium_lib.sodium_init() == -1 then
  return error('sodium_init error')
end

local M = {}

for k,v in pairs(constants) do
  M[k] = v
end

M.crypto_secretbox = lua_crypto_secretbox(
  'crypto_secretbox',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_MACBYTES,
  constants.crypto_secretbox_KEYBYTES,
  constants.crypto_secretbox_ZEROBYTES,
  constants.crypto_secretbox_BOXZEROBYTES)

M.crypto_secretbox_open = lua_crypto_secretbox_open(
  'crypto_secretbox_open',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_MACBYTES,
  constants.crypto_secretbox_KEYBYTES,
  constants.crypto_secretbox_ZEROBYTES,
  constants.crypto_secretbox_BOXZEROBYTES)

M.crypto_secretbox_xsalsa20poly1305 = lua_crypto_secretbox(
  'crypto_secretbox_xsalsa20poly1305',
  constants.crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_MACBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_KEYBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES)

M.crypto_secretbox_xsalsa20poly1305_open = lua_crypto_secretbox_open(
  'crypto_secretbox_xsalsa20poly1305_open',
  constants.crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_MACBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_KEYBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES)

M.crypto_secretbox_easy = lua_crypto_secretbox_easy(
  'crypto_secretbox_easy',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_MACBYTES,
  constants.crypto_secretbox_KEYBYTES)

M.crypto_secretbox_open_easy = lua_crypto_secretbox_open_easy(
  'crypto_secretbox_open_easy',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_MACBYTES,
  constants.crypto_secretbox_KEYBYTES)

M.crypto_secretbox_xchacha20poly1305_easy = lua_crypto_secretbox_easy(
  'crypto_secretbox_xchacha20poly1305_easy',
  constants.crypto_secretbox_xchacha20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xchacha20poly1305_MACBYTES,
  constants.crypto_secretbox_xchacha20poly1305_KEYBYTES)

M.crypto_secretbox_xchacha20poly1305_open_easy = lua_crypto_secretbox_open_easy(
  'crypto_secretbox_xchacha20poly1305_open_easy',
  constants.crypto_secretbox_xchacha20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xchacha20poly1305_MACBYTES,
  constants.crypto_secretbox_xchacha20poly1305_KEYBYTES)

M.crypto_secretbox_detached = lua_crypto_secretbox_detached(
  'crypto_secretbox_detached',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_MACBYTES,
  constants.crypto_secretbox_KEYBYTES)

M.crypto_secretbox_open_detached = lua_crypto_secretbox_open_detached(
  'crypto_secretbox_open_detached',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_MACBYTES,
  constants.crypto_secretbox_KEYBYTES)

M.crypto_secretbox_xchacha20poly1305_detached = lua_crypto_secretbox_detached(
  'crypto_secretbox_xchacha20poly1305_detached',
  constants.crypto_secretbox_xchacha20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xchacha20poly1305_MACBYTES,
  constants.crypto_secretbox_xchacha20poly1305_KEYBYTES)

M.crypto_secretbox_xchacha20poly1305_open_detached = lua_crypto_secretbox_open_detached(
  'crypto_secretbox_xchacha20poly1305_open_detached',
  constants.crypto_secretbox_xchacha20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xchacha20poly1305_MACBYTES,
  constants.crypto_secretbox_xchacha20poly1305_KEYBYTES)

M.crypto_secretbox_keygen = lua_crypto_secretbox_keygen(
  'crypto_secretbox_keygen',
  constants.crypto_secretbox_KEYBYTES)

M.crypto_secretbox_keygen = lua_crypto_secretbox_keygen(
  'crypto_secretbox_keygen',
  constants.crypto_secretbox_KEYBYTES)

return M
