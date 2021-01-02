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
