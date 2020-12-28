local ffi = require'ffi'
local string_len = string.len
local string_format = string.format
local ffi_string = ffi.string

local char_array = ffi.typeof('char[?]')

local sodium_lib
local crypto_box_PUBLICKEYBYTES
local crypto_box_SECRETKEYBYTES
local crypto_box_MACBYTES
local crypto_box_NONCEBYTES
local crypto_box_SEEDBYTES
local crypto_box_BEFORENMBYTES

local function test_cspace()
  if ffi.C.crypto_box_publickeybytes then
    return ffi.C
  end
end

local c_pointers = { ... }

if #c_pointers > 1 then
  sodium_lib = {}
  crypto_box_PUBLICKEYBYTES = c_pointers[1]
  crypto_box_SECRETKEYBYTES = c_pointers[2]
  crypto_box_MACBYTES       = c_pointers[3]
  crypto_box_NONCEBYTES     = c_pointers[4]
  crypto_box_SEEDBYTES      = c_pointers[5]
  crypto_box_BEFORENMBYTES  = c_pointers[6]

  sodium_lib.crypto_box_keypair = ffi.cast([[
    int (*)(unsigned char *, unsigned char *)
  ]],c_pointers[7])

else
  ffi.cdef([[
    size_t crypto_box_publickeybytes(void);
    size_t crypto_box_secretkeybytes(void);
    size_t crypto_box_macbytes(void);
    size_t crypto_box_noncebytes(void);
    size_t crypto_box_seedbytes(void);
    size_t crypto_box_beforenmbytes(void);
  ]])
  do
    local ok, lib = pcall(test_cspace)
    if ok then
      sodium_lib = lib
    else
      sodium_lib = ffi.load('sodium')
    end
  end

  crypto_box_PUBLICKEYBYTES = tonumber(sodium_lib.crypto_box_publickeybytes())
  crypto_box_SECRETKEYBYTES = tonumber(sodium_lib.crypto_box_secretkeybytes())
  crypto_box_MACBYTES       = tonumber(sodium_lib.crypto_box_macbytes())
  crypto_box_NONCEBYTES     = tonumber(sodium_lib.crypto_box_noncebytes())
  crypto_box_SEEDBYTES      = tonumber(sodium_lib.crypto_box_seedbytes())
  crypto_box_BEFORENMBYTES  = tonumber(sodium_lib.crypto_box_beforenmbytes())

  ffi.cdef([[
    int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
  ]])

end

local function lua_crypto_box_keypair()
  local pk = char_array(crypto_box_PUBLICKEYBYTES)
  local sk = char_array(crypto_box_SECRETKEYBYTES)
  if tonumber(sodium_lib.crypto_box_keypair(pk,sk)) == -1 then
    return error('crypto_box_keypair error')
  end
  return ffi_string(pk,crypto_box_PUBLICKEYBYTES),
         ffi_string(sk,crypto_box_SECRETKEYBYTES)
end


local M = {
  PUBLICKEYBYTES = crypto_box_PUBLICKEYBYTES,
  SECRETKEYBYTES = crypto_box_SECRETKEYBYTES,
  MACBYTES       = crypto_box_MACBYTES,
  NONCEBYTES     = crypto_box_NONCEBYTES,
  SEEDBYTES      = crypto_box_SEEDBYTES,
  BEFORENMBYTES  = crypto_box_BEFORENMBYTES,
  keypair = lua_crypto_box_keypair,
}

return M

