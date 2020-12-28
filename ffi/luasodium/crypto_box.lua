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

  sodium_lib.crypto_box_publickeybytes = ffi.cast([[
    size_t (*)(void)
  ]],c_pointers[7])

  sodium_lib.crypto_box_secretkeybytes = ffi.cast([[
    size_t (*)(void)
  ]],c_pointers[8])

  sodium_lib.crypto_box_macbytes = ffi.cast([[
    size_t (*)(void)
  ]],c_pointers[9])

  sodium_lib.crypto_box_noncebytes = ffi.cast([[
    size_t (*)(void)
  ]],c_pointers[10])

  sodium_lib.crypto_box_seedbytes = ffi.cast([[
    size_t (*)(void)
  ]],c_pointers[11])

  sodium_lib.crypto_box_beforenmbytes = ffi.cast([[
    size_t (*)(void)
  ]],c_pointers[12])
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

end

local M = {
  PUBLICKEYBYTES = crypto_box_PUBLICKEYBYTES,
  SECRETKEYBYTES = crypto_box_SECRETKEYBYTES,
  MACBYTES       = crypto_box_MACBYTES,
  NONCEBYTES     = crypto_box_NONCEBYTES,
  SEEDBYTES      = crypto_box_SEEDBYTES,
  BEFORENMBYTES  = crypto_box_BEFORENMBYTES,
}

return M

