-- uses sodium functions to find constant values,
-- ie: crypto_secretbox_KEYBYTES as available as:
--   --size_t crypto_secretbox_keybytes(void)
--
-- the Pure FFI mode uses these functions to find
-- constants.
local function constant_loader(sodium_lib, constant_keys)
  local ffi = require'ffi'

  local constants = {}

  for _,c in ipairs(constant_keys) do
    local n = c.name
    local val

    if c['type'] == 0 then
      ffi.cdef('int ' .. n:lower() .. '(void);')
      val = tonumber(sodium_lib[n:lower()]())
    elseif c['type'] == 1 then
      ffi.cdef('size_t ' .. n:lower() .. '(void);')
      val = tonumber(sodium_lib[n:lower()]())
    elseif c['type'] == 2 then
      ffi.cdef('const char * ' .. n:lower() .. '(void);')
      val = ffi.string(sodium_lib[n:lower()]())
    end

    constants[n] = val
  end

  return constants
end

return constant_loader
