local lib   = require'luasodium'

for i=1,100 do
do
  local data1 = 'abcdef'
  local data2 = 'ghefgi'
  assert(lib.sodium_memcmp(data1,data2,6) == false)
end

do
  local data1 = 'abcdef'
  local data2 = 'abcdef'
  assert(lib.sodium_memcmp(data1,data2,6) == true)
end

do
  assert(lib.sodium_bin2hex('hello') == '68656c6c6f')
  assert(lib.sodium_bin2hex('\0\0\0\0\0\0') == '000000000000')
  assert(lib.sodium_bin2hex('\0') == '00')
  assert(lib.sodium_bin2hex('\0\0') == '0000')
end

do
  local hex_str = '68:65:6c 6c: 6f00'
  assert(lib.sodium_hex2bin('68656c6c6f') == 'hello')
  assert(lib.sodium_hex2bin(hex_str,': ') == 'hello\0')
  local bin, rem = lib.sodium_hex2bin(hex_str .. 'Hello', ': ')
  assert(bin == 'hello\0')
  assert(rem == 'Hello')
end

do
 assert(lib.sodium_bin2base64('Hello there',lib.sodium_base64_VARIANT_ORIGINAL) == 'SGVsbG8gdGhlcmU=')
 assert(lib.sodium_bin2base64('Hello there',lib.sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 'SGVsbG8gdGhlcmU')
end

do
 assert(lib.sodium_base642bin('SGVsbG8gdGhlcmU=',lib.sodium_base64_VARIANT_ORIGINAL) == 'Hello there')
 assert(lib.sodium_base642bin('SGVsbG8gdGhlcmU',lib.sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 'Hello there')
end

do
  assert(lib.sodium_increment('\0\0\0\0') == '\1\0\0\0')
  assert(lib.sodium_add('\1\0\0\0','\2\0\0\0') == '\3\0\0\0')
  assert(lib.sodium_sub('\3\0\0\0','\1\0\0\0') == '\2\0\0\0')
  assert(lib.sodium_compare('\3\0\0\0','\1\0\0\0') == 1)
  assert(lib.sodium_compare('\1\0\0\0','\1\0\0\0') == 0)
  assert(lib.sodium_compare('\1\0\0\0','\2\0\0\0') == -1)
  assert(lib.sodium_is_zero('\0\0\0\0') == true)
  assert(lib.sodium_is_zero('\1\0\0\1') == false)
end

do
  local original = '\1\2\3\4\5\6\7'
  local padded = lib.sodium_pad(original,8)
  assert(string.len(padded) == 8)
  local res = lib.sodium_unpad(padded,8)
  assert(res == original)
end
end

print('success')
