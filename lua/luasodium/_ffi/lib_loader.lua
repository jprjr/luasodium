-- used by the pure-ffi, returns a
-- reference to the sodium library
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

  local lib

  do
    local ok = pcall(test_cspace)
    if ok then
      lib = ffi.C
    else
      local is_windows = package.config:sub(1,1) == '\\'
      if is_windows then
        lib = ffi.load('libsodium')
      else
        lib = ffi.load('sodium')
      end
    end
  end

  for f, sig in pairs(signatures) do
    ffi.cdef(string_format(sig,f))
  end

  return lib
end

return lib_loader
