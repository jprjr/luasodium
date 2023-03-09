-- returns a 'libs' table
-- used by the ffi-in-a-c-module
return function(signatures,pointers)

  local ffi = require'ffi'
  local string_format = string.format

  local lib = {}

  for k,f in pairs(pointers) do
    if signatures[k] then
      lib[k] = ffi.cast(string_format(signatures[k],'(*)'),f)
    end
  end

  return lib
end
