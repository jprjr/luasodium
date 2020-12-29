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

local function test_cspace()
  if ffi.C.sodium_init then
    return ffi.C
  end
end

local c_pointers = { ... }


if #c_pointers == 3 and
  type(c_pointers[1]) == 'userdata' then
  sodium_lib = {}

  sodium_lib.sodium_init = ffi.cast([[
    int (*)(void)
  ]],c_pointers[1])

  constants = c_pointers[2]

  for _,f in ipairs(c_pointers[3]) do
    sodium_lib[f.name] = ffi.cast(f.signature,f.func)
  end

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

  for _,f in ipairs({'crypto_secretbox',
                     'crypto_secretbox_open',
                     'crypto_secretbox_xsalsa20poly1305',
                     'crypto_secretbox_xsalsa20poly1305_open',
                     'crypto_secretbox_easy',
                     'crypto_secretbox_open_easy',
                     'crypto_secretbox_xchacha20poly1305_easy',
                     'crypto_secretbox_xchacha20poly1305_open_easy'}) do

    ffi.cdef('int ' .. f .. [[(unsigned char *c, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *n,
                            const unsigned char *k);]])
  end

  for _,f in ipairs({'crypto_secretbox_detached',
                     'crypto_secretbox_xchachapoly1305_detached'}) do

    ffi.cdef('int ' .. f .. [[(unsigned char *c, unsigned char *mac,
                            const unsigned char *m,
                            unsigned long long mlen, const unsigned char *n,
                            const unsigned char *k);]])
  end

  for _,f in ipairs({'crypto_secretbox_open_detached',
                     'crypto_secretbox_xchachapoly1305_open_detached'}) do

    ffi.cdef('int ' .. f .. [[(unsigned char *m, const unsigned char *c,
                            const unsigned char *mac,
                            unsigned long long mlen, const unsigned char *n,
                            const unsigned char *k);]])
  end

  for _,f in ipairs({'crypto_secretbox_keygen',
                     'crypto_secretbox_xsalsa20poly1305_keygen'}) do
    ffi.cdef('void ' .. f .. [[(unsigned char *);]])
  end

end

local function lua_crypto_secretbox(fname,noncebytes,keybytes,inputzerobytes,outputzerobytes,macbytes)
  return function(input, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local inputlen = string_len(input)
    local outputlen = inputlen + macbytes

    if outputlen < 0 then
      return error(string.format('wrong input size, expected at least: %d',
        macbytes > 0 and macbytes or -macbytes))
    end

    if string_len(nonce) ~= noncebytes then
      return error(string_format('wrong nonce size, expected: %d',
        noncebytes))
    end

    if string_len(key) ~= keybytes then
      return error(string_format('wrong key size, expected: %d',
        keybytes))
    end

    local tmp_input = char_array(inputlen + inputzerobytes)
    ffi.fill(tmp_input,inputzerobytes,0)
    ffi.copy(tmp_input+inputzerobytes,input,inputlen)

    local output = char_array(outputlen + outputzerobytes)
    ffi.fill(output,outputzerobytes,0)

    if sodium_lib[fname](
      output,tmp_input,inputlen+inputzerobytes,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end
    return ffi_string(output+outputzerobytes,outputlen)
  end
end

local function lua_crypto_secretbox_easy(fname,noncebytes,keybytes,macbytes)
  return function(input, nonce, key)
    if not key then
      return error('requires 3 arguments')
    end

    local inputlen = string_len(input)
    local outputlen = inputlen + macbytes

    if outputlen < 0 then
      return error(string.format('wrong input size, expected at least: %d',
        macbytes > 0 and macbytes or -macbytes))
    end

    if string_len(nonce) ~= noncebytes then
      return error(string_format('wrong nonce size, expected: %d',
        noncebytes))
    end

    if string_len(key) ~= keybytes then
      return error(string_format('wrong key size, expected: %d',
        keybytes))
    end

    local output = char_array(outputlen)

    if sodium_lib[fname](
      output,input,inputlen,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end
    return ffi_string(output,outputlen)
  end
end


local function lua_crypto_secretbox_detached(fname, noncebytes, keybytes, macbytes)
  return function(message,nonce,key)
    if not key then
      return error('requires 3 arguments')
    end

    local mlen = string_len(message)

    if string_len(nonce) ~= noncebytes then
      return error(string_format('wrong nonce size, expected: %d',
        noncebytes))
    end

    if string_len(key) ~= keybytes then
      return error(string_format('wrong key size, expected: %d',
        keybytes))
    end

    local c = char_array(mlen)
    local mac = char_array(macbytes)

    if sodium_lib[fname](
      c,mac,message,mlen,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end
    return ffi_string(c,mlen), ffi_string(mac,macbytes)
  end
end

local function lua_crypto_secretbox_open_detached(fname, noncebytes, keybytes, macbytes)
  return function(cipher,mac,nonce,key)
    if not key then
      return error('requires 4 arguments')
    end

    local clen = string_len(cipher)

    if string_len(mac) ~= macbytes then
      return error(string_format('wrong mac size, expected: %d',
        macbytes))
    end

    if string_len(nonce) ~= noncebytes then
      return error(string_format('wrong nonce size, expected: %d',
        noncebytes))
    end

    if string_len(key) ~= keybytes then
      return error(string_format('wrong key size, expected: %d',
        noncebytes))
    end

    local m = char_array(clen)
    if sodium_lib[fname](
      m,cipher,mac,clen,
      nonce,key) == -1  then
      return error(fname .. ' error')
    end
    return ffi_string(m,clen)
  end
end

local function lua_crypto_secretbox_keygen(fname,size)
  return function()
    local k = char_array(size)
    sodium_lib[fname](k)
    return ffi_string(k,size)
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
  constants.crypto_secretbox_KEYBYTES,
  constants.crypto_secretbox_ZEROBYTES,
  constants.crypto_secretbox_BOXZEROBYTES,
  constants.crypto_secretbox_MACBYTES)

M.crypto_secretbox_open = lua_crypto_secretbox(
  'crypto_secretbox_open',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_KEYBYTES,
  constants.crypto_secretbox_BOXZEROBYTES,
  constants.crypto_secretbox_ZEROBYTES,
  -constants.crypto_secretbox_MACBYTES)

M.crypto_secretbox_xsalsa20poly1305 = lua_crypto_secretbox(
  'crypto_secretbox_xsalsa20poly1305',
  constants.crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_KEYBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_MACBYTES)

M.crypto_secretbox_xsalsa20poly1305_open = lua_crypto_secretbox(
  'crypto_secretbox_xsalsa20poly1305_open',
  constants.crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_KEYBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,
  constants.crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
  -constants.crypto_secretbox_xsalsa20poly1305_MACBYTES)

M.crypto_secretbox_easy = lua_crypto_secretbox_easy(
  'crypto_secretbox_easy',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_KEYBYTES,
  constants.crypto_secretbox_MACBYTES)

M.crypto_secretbox_open_easy = lua_crypto_secretbox_easy(
  'crypto_secretbox_open_easy',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_KEYBYTES,
  -constants.crypto_secretbox_MACBYTES)

M.crypto_secretbox_xchacha20poly1305_easy = lua_crypto_secretbox_easy(
  'crypto_secretbox_xchacha20poly1305_easy',
  constants.crypto_secretbox_xchacha20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xchacha20poly1305_KEYBYTES,
  constants.crypto_secretbox_xchacha20poly1305_MACBYTES)

M.crypto_secretbox_xchacha20poly1305_open_easy = lua_crypto_secretbox_easy(
  'crypto_secretbox_xchacha20poly1305_open_easy',
  constants.crypto_secretbox_xchacha20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xchacha20poly1305_KEYBYTES,
  -constants.crypto_secretbox_xchacha20poly1305_MACBYTES)

M.crypto_secretbox_detached = lua_crypto_secretbox_detached(
  'crypto_secretbox_detached',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_KEYBYTES,
  constants.crypto_secretbox_MACBYTES)

M.crypto_secretbox_open_detached = lua_crypto_secretbox_open_detached(
  'crypto_secretbox_open_detached',
  constants.crypto_secretbox_NONCEBYTES,
  constants.crypto_secretbox_KEYBYTES,
  constants.crypto_secretbox_MACBYTES)

M.crypto_secretbox_xchacha20poly1305_detached = lua_crypto_secretbox_detached(
  'crypto_secretbox_xchacha20poly1305_detached',
  constants.crypto_secretbox_xchacha20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xchacha20poly1305_KEYBYTES,
  constants.crypto_secretbox_xchacha20poly1305_MACBYTES)

M.crypto_secretbox_xchacha20poly1305_open_detached = lua_crypto_secretbox_open_detached(
  'crypto_secretbox_xchacha20poly1305_open_detached',
  constants.crypto_secretbox_xchacha20poly1305_NONCEBYTES,
  constants.crypto_secretbox_xchacha20poly1305_KEYBYTES,
  constants.crypto_secretbox_xchacha20poly1305_MACBYTES)

M.crypto_secretbox_keygen = lua_crypto_secretbox_keygen(
  'crypto_secretbox_keygen',
  constants.crypto_secretbox_KEYBYTES)

M.crypto_secretbox_keygen = lua_crypto_secretbox_keygen(
  'crypto_secretbox_keygen',
  constants.crypto_secretbox_KEYBYTES)

return M
