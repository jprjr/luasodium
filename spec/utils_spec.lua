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
  lib = require'luasodium.utils'
  assert(type(lib) == 'table')
  libs['luasodium.utils'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.utils.core', 'luasodium.utils.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end

for m,lib in pairs(libs) do
  describe('utils: ' .. m, function()
    it('should memcmp false', function()
      local data1 = 'abcdef'
      local data2 = 'ghefgi'
      assert(lib.sodium_memcmp(data1,data2,6) == false)
    end)

    it('should memcmp true', function()
      local data1 = 'abcdef'
      local data2 = 'abcdef'
      assert(lib.sodium_memcmp(data1,data2,6) == true)
    end)

    it('should bin2hex', function()
      assert(lib.sodium_bin2hex('hello') == '68656c6c6f')
      assert(lib.sodium_bin2hex('\0\0\0\0\0\0') == '000000000000')
      assert(lib.sodium_bin2hex('\0') == '00')
      assert(lib.sodium_bin2hex('\0\0') == '0000')
    end)

    it('should hex2bin', function()
      local hex_str = '68:65:6c 6c: 6f00'
      assert(lib.sodium_hex2bin('68656c6c6f') == 'hello')
      assert(lib.sodium_hex2bin(hex_str,': ') == 'hello\0')
      local bin, rem = lib.sodium_hex2bin(hex_str .. 'Hello', ': ')
      assert(bin == 'hello\0')
      assert(rem == 'Hello')
    end)

    it('should bin2base64', function()
     assert(lib.sodium_bin2base64('Hello there',lib.sodium_base64_VARIANT_ORIGINAL) == 'SGVsbG8gdGhlcmU=')
     assert(lib.sodium_bin2base64('Hello there',lib.sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 'SGVsbG8gdGhlcmU')
    end)

    it('should base642bin', function()
     assert(lib.sodium_base642bin('SGVsbG8gdGhlcmU=',lib.sodium_base64_VARIANT_ORIGINAL) == 'Hello there')
     assert(lib.sodium_base642bin('SGVsbG8gdGhlcmU',lib.sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 'Hello there')
    end)

    it('should increment/decrement/compare', function()
      assert(lib.sodium_increment('\0\0\0\0') == '\1\0\0\0')
      assert(lib.sodium_add('\1\0\0\0','\2\0\0\0') == '\3\0\0\0')
      assert(lib.sodium_sub('\3\0\0\0','\1\0\0\0') == '\2\0\0\0')
      assert(lib.sodium_compare('\3\0\0\0','\1\0\0\0') == 1)
      assert(lib.sodium_compare('\1\0\0\0','\1\0\0\0') == 0)
      assert(lib.sodium_compare('\1\0\0\0','\2\0\0\0') == -1)
      assert(lib.sodium_is_zero('\0\0\0\0') == true)
      assert(lib.sodium_is_zero('\1\0\0\1') == false)
    end)

    it('should pad/unpad', function()
      local original = '\1\2\3\4\5\6\7'
      local padded = lib.sodium_pad(original,8)
      assert(string.len(padded) == 8)
      local res = lib.sodium_unpad(padded,8)
      assert(res == original)
    end)
  end)
end

