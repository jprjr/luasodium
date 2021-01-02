-- returns a 'libs' table
return function(signatures,pointers)

  local ffi = require'ffi'
  local string_format = string.format

  local libs = {
    sodium = {}
  }
  libs.C = libs.sodium

  for k,f in pairs(pointers) do
    if signatures[k] then
      libs.sodium[k] = ffi.cast(string_format(signatures[k],'(*)'),f)
    end
  end

  return libs
end
