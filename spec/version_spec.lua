local libs = {}

-- these should always load, regardless of Lua interpreter
do
  local lib = require'luasodium'
  assert(type(lib) == 'table')
  libs.luasodium = lib
  lib = require'luasodium.version'
  assert(type(lib) == 'table')
  libs['luasodium.version'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.version.core', 'luasodium.version.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end

for m,lib in pairs(libs) do
  describe('version: ' .. m, function()
    it('should work', function()
      assert(type(lib._VERSION) == 'string')
      assert(type(lib.sodium_version_string()) == 'string')
      assert(type(lib.sodium_library_version_major()) == 'number')
      assert(type(lib.sodium_library_version_minor()) == 'number')
      assert(type(lib.sodium_library_minimal()) == 'number')
    end)
  end)
end
