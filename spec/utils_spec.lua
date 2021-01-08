require('busted.runner')()

local mode = os.getenv('TESTMODE')
if not mode then
  mode = 'core'
end

local lib = require('luasodium.' .. mode)

describe('utils', function()
  it('should init', function()
    assert(lib.sodium_init() == true)
  end)

  it('should reject bad memcmp calls', function()
    assert(pcall(lib.sodium_memcmp) == false)
  end)

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

  it('should reject bad bin2hex calls', function()
    assert(pcall(lib.sodium_bin2hex) == false)
  end)

  it('should bin2hex', function()
    assert(lib.sodium_bin2hex('hello') == '68656c6c6f')
    assert(lib.sodium_bin2hex('\0\0\0\0\0\0') == '000000000000')
    assert(lib.sodium_bin2hex('\0') == '00')
    assert(lib.sodium_bin2hex('\0\0') == '0000')
  end)

  it('should reject bad hex2bin calls', function()
    assert(pcall(lib.sodium_hex2bin) == false)
  end)

  it('should hex2bin', function()
    local hex_str = '68:65:6c 6c: 6f00'
    assert(lib.sodium_hex2bin('68656c6c6f') == 'hello')
    assert(lib.sodium_hex2bin(hex_str,': ') == 'hello\0')
    local bin, rem = lib.sodium_hex2bin(hex_str .. 'Hello', ': ')
    assert(bin == 'hello\0')
    assert(rem == 'Hello')
  end)

  it('should reject bad bin2base64 calls', function()
    assert(pcall(lib.sodium_bin2base64) == false)
  end)

  it('should bin2base64', function()
   assert(lib.sodium_bin2base64('Hello there',lib.sodium_base64_VARIANT_ORIGINAL) == 'SGVsbG8gdGhlcmU=')
   assert(lib.sodium_bin2base64('Hello there',lib.sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 'SGVsbG8gdGhlcmU')
   assert(lib.sodium_bin2base64('Hello there',lib.sodium_base64_VARIANT_URLSAFE) == 'SGVsbG8gdGhlcmU=')
   assert(lib.sodium_bin2base64('Hello there',lib.sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 'SGVsbG8gdGhlcmU')
   assert(pcall(lib.sodium_bin2base64,'Hello there',0) == false)
  end)

  it('should reject bad base642bin calls', function()
    assert(pcall(lib.sodium_base642bin) == false)
  end)

  it('should base642bin', function()
   assert(lib.sodium_base642bin('SGVsbG8gdGhlcmU=',lib.sodium_base64_VARIANT_ORIGINAL) == 'Hello there')
   assert(lib.sodium_base642bin('SGVsbG8gdGhlcmU',lib.sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 'Hello there')
   assert(lib.sodium_base642bin('SGVsbG8gdGhlcmU=',lib.sodium_base64_VARIANT_URLSAFE) == 'Hello there')
   assert(lib.sodium_base642bin('SGVsbG8gdGhlcmU',lib.sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 'Hello there')
   assert(lib.sodium_base642bin('  SGVsbG8gdGhlcmU  ',lib.sodium_base64_VARIANT_URLSAFE_NO_PADDING,' ') == 'Hello there')
   local bin, extra = lib.sodium_base642bin('  SGVsbG8gdGhlcmU  {extradata}',lib.sodium_base64_VARIANT_URLSAFE_NO_PADDING,' ')
   assert(bin == 'Hello there')
   assert(extra == '{extradata}')
   assert(pcall(lib.sodium_base642bin,'SGVsbG8gdGhlcmU',0) == false)
  end)

  it('should increment/decrement/compare', function()
    assert(lib.sodium_increment('\0\0\0\0') == '\1\0\0\0')
    assert(lib.sodium_add('\1\0\0\0','\2\0\0\0') == '\3\0\0\0')
    assert(lib.sodium_sub('\3\0\0\0','\1\0\0\0') == '\2\0\0\0')
    assert(lib.sodium_compare('\3\0\0\0','\1\0\0\0') == 1)
    assert(lib.sodium_compare('\1\0\0\0','\1\0\0\0') == 0)
    assert(lib.sodium_compare('\1\0\0\0','\2\0\0\0') == -1)
    assert(pcall(lib.sodium_compare,'\0\0\0','\2\0\0\0') == false)
    assert(pcall(lib.sodium_add,'\0\0\0','\2\0\0\0') == false)
    assert(pcall(lib.sodium_sub,'\0\0\0','\2\0\0\0') == false)
    assert(lib.sodium_is_zero('\0\0\0\0') == true)
    assert(lib.sodium_is_zero('\1\0\0\1') == false)
    assert(pcall(lib.sodium_is_zero) == false)
    assert(pcall(lib.sodium_increment) == false)
    assert(pcall(lib.sodium_add) == false)
    assert(pcall(lib.sodium_sub) == false)
  end)

  it('should pad/unpad', function()
    local original = '\1\2\3\4\5\6\7'
    local padded = lib.sodium_pad(original,8)
    assert(string.len(padded) == 8)
    local res = lib.sodium_unpad(padded,8)
    assert(res == original)
    assert(pcall(lib.sodium_pad) == false)
    assert(pcall(lib.sodium_unpad) == false)
  end)
end)
