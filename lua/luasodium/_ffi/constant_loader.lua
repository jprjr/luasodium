-- uses sodium functions to find constant values,
-- ie: crypto_secretbox_KEYBYTES as available as:
--   --size_t crypto_secretbox_keybytes(void)
--
-- the Pure FFI mode uses these functions to find
-- constants.
local function constant_loader(sodium_lib, constant_keys)
  local ffi = require'ffi'
  local tonumber = tonumber

  local constants = {}

  for _,c in ipairs(constant_keys) do
    ffi.cdef('size_t ' .. c:lower() .. '(void);')
    constants[c] = tonumber(sodium_lib[c:lower()]())
  end

  return constants
end

return constant_loader
