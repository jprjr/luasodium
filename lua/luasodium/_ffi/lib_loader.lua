-- used by the pure-ffi, returns a
-- 'libs' table with references to
-- the C and sodium libraries
local function lib_loader(signatures)

  local ffi = require'ffi'
  local string_format = string.format

  ffi.cdef([[
    int sodium_init(void);
  ]])

  local function test_cspace()
    if ffi.C.sodium_init then
      return ffi.C
    end
    return false
  end

  local libs = {
    C = ffi.C
  }

  do
    local ok = pcall(test_cspace)
    if ok then
      libs.sodium = libs.C
    else
      libs.sodium = ffi.load('sodium')
    end
  end

  for f, sig in pairs(signatures) do
    ffi.cdef(string_format(sig,f))
  end

  return libs
end

return lib_loader
