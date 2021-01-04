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
  lib = require'luasodium.crypto_scalarmult'
  assert(type(lib) == 'table')
  libs['luasodium.crypto_scalarmult'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.crypto_scalarmult.core', 'luasodium.crypto_scalarmult.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end

for m,lib in pairs(libs) do
  describe('crypto_scalarmult: ' .. m, function()
    it('should work', function()
      local n = string.rep('\0',lib.crypto_scalarmult_SCALARBYTES)
      local q = lib.crypto_scalarmult_base(n)
      assert(string.len(q) == lib.crypto_scalarmult_BYTES)
      local p = lib.crypto_scalarmult(n,q)
    end)
  end)
end

