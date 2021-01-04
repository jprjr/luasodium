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
  lib = require'luasodium.crypto_stream'
  assert(type(lib) == 'table')
  libs['luasodium.crypto_stream'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.crypto_stream.core', 'luasodium.crypto_stream.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end

local expected_str = {
  186, 110, 38, 223, 75, 46, 162, 207,
  100, 210, 211, 99, 102, 35, 181, 244,
}

for m,lib in pairs(libs) do
  describe('crypto_stream: ' .. m, function()
    local nonce = string.rep('\0',lib.crypto_stream_NONCEBYTES)
    local key = string.rep('\0',lib.crypto_stream_KEYBYTES)


    it('should work', function()
      local str = lib.crypto_stream(16,nonce,key)
      assert(string.len(str) == 16)
      for i=1,16 do
        assert(expected_str[i] == string.byte(str,i))
      end

      local x = lib.crypto_stream_xor('message',nonce,key)
      assert(string.len(x) == string.len('message'))
      assert(lib.crypto_stream_xor(x,nonce,key) == 'message')

      local k = lib.crypto_stream_keygen()
      assert(string.len(k) == lib.crypto_stream_KEYBYTES)
    end)

    it('should reject bad calls', function()
      assert(pcall(lib.crypto_stream) == false)
      assert(pcall(lib.crypto_stream,0,'','') == false)
      assert(pcall(lib.crypto_stream,0,string.rep('\0',lib.crypto_stream_NONCEBYTES),'') == false)
      assert(pcall(lib.crypto_stream_xor) == false)
      assert(pcall(lib.crypto_stream_xor,'','','') == false)
      assert(pcall(lib.crypto_stream_xor,'',string.rep('\0',lib.crypto_stream_NONCEBYTES),'') == false)
    end)
  end)
end

