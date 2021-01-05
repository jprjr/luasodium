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
  lib = require'luasodium.randombytes'
  assert(type(lib) == 'table')
  libs['luasodium.randombytes'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.randombytes.core', 'luasodium.randombytes.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end

for m,lib in pairs(libs) do
  describe('crypto_box: ' .. m, function()

    it('should work', function()
      local r = lib.randombytes_random()
      local seed = string.rep('\0',lib.randombytes_SEEDBYTES)
      assert(type(r) == 'number')
      assert(lib.randombytes_uniform(1) == 0)
      assert(string.len(lib.randombytes_buf(10)) == 10)
      local result = lib.randombytes_buf_deterministic(10,seed)
      local result_vals = {
        161,
        31,
        143,
        18,
        208,
        135,
        111,
        115,
        109,
        45,
      }

      for i=1,10 do
        assert(string.byte(result,i) == result_vals[i])
      end
      lib.randombytes_stir()
    end)

    it('should reject bad calls', function()
      assert(pcall(lib.randombytes_uniform) == false)
      assert(pcall(lib.randombytes_buf) == false)
      assert(pcall(lib.randombytes_buf_deterministic) == false)
      assert(pcall(lib.randombytes_buf_deterministic,10,'') == false)
    end)
  end)
end


