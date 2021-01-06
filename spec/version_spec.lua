local libs = {}

local function describe_stub(_,cb)
  cb()
end

local function it_stub(_,cb)
  cb()
end

do
  local ok, runner = pcall(require,'busted.runner')
  if ok then
    runner()
  end
end

if not describe then
  describe = describe_stub
  it = it_stub
end


-- these should always load, regardless of Lua interpreter
do
  local lib = require'luasodium'
  assert(type(lib) == 'table')
  libs.luasodium = lib
  lib = require'luasodium.version'
  assert(type(lib) == 'table')
  libs['luasodium.version'] = lib
end

for _,t in ipairs({'core','ffi','pureffi'}) do
  for _,m in ipairs({'luasodium.' .. t, 'luasodium.version.' .. t}) do
    local ok, lib = pcall(require,m)
    if ok then
      libs[m] = lib
    end
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

