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
    local n

    if type(c) == 'string' then
      ffi.cdef('size_t ' .. c:lower() .. '(void);')
      constants[c] = tonumber(sodium_lib[c:lower()]())
    elseif type(c) == 'table' then
      n = c.name
      if c['type'] == 0 then
        ffi.cdef('int ' .. n:lower() .. '(void);')
        constants[n] = tonumber(sodium_lib[n:lower()]())
      elseif c['type'] == 1 then
        ffi.cdef('size_t ' .. n:lower() .. '(void);')
        constants[n] = tonumber(sodium_lib[n:lower()]())
      elseif c['type'] == 2 then
        ffi.cdef('const char * ' .. n:lower() .. '(void);')
        constants[n] = ffi.string(sodium_lib[n:lower()]())
      end
    end
  end

  return constants
end

return constant_loader
