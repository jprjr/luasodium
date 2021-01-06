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
  lib = require'luasodium.crypto_verify'
  assert(type(lib) == 'table')
  libs['luasodium.crypto_verify'] = lib
end

for _,t in ipairs({'core','ffi','pureffi'}) do
  for _,m in ipairs({'luasodium.' .. t, 'luasodium.crypto_crypto_verify.' .. t}) do
    local ok, lib = pcall(require,m)
    if ok then
      libs[m] = lib
    end
  end
end

local test1_16 = string.rep('\0',16)
local test2_16 = string.rep('\0',16)
local test3_16 = string.rep('\1',16)

local test1_32 = string.rep('\0',32)
local test2_32 = string.rep('\0',32)
local test3_32 = string.rep('\1',32)

local test1_24 = string.rep('\0',24)
local test2_24 = string.rep('\0',24)
local test3_24 = string.rep('\1',24)

for m,lib in pairs(libs) do
  describe('crypto_verify: ' .. m, function()

    it('should work', function()
      assert(lib.crypto_verify_16(test1_16,test2_16) == true)
      assert(lib.crypto_verify_16(test1_16,test3_16) == false)

      assert(lib.crypto_verify_32(test1_32,test2_32) == true)
      assert(lib.crypto_verify_32(test1_32,test3_32) == false)

    end)

    it('should reject bad calls',function()
      assert(pcall(lib.crypto_verify_16) == false)
      assert(pcall(lib.crypto_verify_16,test1_16,test2_24) == false)
      assert(pcall(lib.crypto_verify_16,test1_24,test2_24) == false)
    end)
  end)
end

