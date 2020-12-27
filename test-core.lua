local luasodium   = require'luasodium'

assert(luasodium.init())

for i=1,100 do
do
  local data1 = 'abcdef'
  local data2 = 'ghefgi'
  assert(luasodium.memcmp(data1,data2,6) == false)
end

do
  local data1 = 'abcdef'
  local data2 = 'abcdef'
  assert(luasodium.memcmp(data1,data2,6) == true)
end

do
  assert(luasodium.bin2hex('hello',5) == '68656c6c6f')
  assert(luasodium.bin2hex('\0\0\0\0\0\0',6) == '000000000000')
  assert(luasodium.bin2hex('\0\0\0\0\0\0',1) == '00')
end

do
  local hex_str = '68:65:6c 6c: 6f00'
  assert(luasodium.hex2bin('68656c6c6f',10) == 'hello')
  assert(luasodium.hex2bin(hex_str,string.len(hex_str),': ') == 'hello\0')
  local bin, rem = luasodium.hex2bin(hex_str .. 'Hello', string.len(hex_str) + 5, ': ')
  assert(bin == 'hello\0')
  assert(rem == 'Hello')
end

do
 assert(luasodium.bin2base64('Hello there',11,luasodium.base64_VARIANT_ORIGINAL) == 'SGVsbG8gdGhlcmU=')
 assert(luasodium.bin2base64('Hello there',11,luasodium.base64_VARIANT_ORIGINAL_NO_PADDING) == 'SGVsbG8gdGhlcmU')
end

do
 assert(luasodium.base642bin('SGVsbG8gdGhlcmU=',16,luasodium.base64_VARIANT_ORIGINAL) == 'Hello there')
 assert(luasodium.base642bin('SGVsbG8gdGhlcmU',15,luasodium.base64_VARIANT_ORIGINAL_NO_PADDING) == 'Hello there')
end

do
  assert(luasodium.increment('\0\0\0\0') == '\1\0\0\0')
  assert(luasodium.add('\1\0\0\0','\2\0\0\0') == '\3\0\0\0')
  assert(luasodium.sub('\3\0\0\0','\1\0\0\0') == '\2\0\0\0')
  assert(luasodium.compare('\3\0\0\0','\1\0\0\0') == 1)
  assert(luasodium.compare('\1\0\0\0','\1\0\0\0') == 0)
  assert(luasodium.compare('\1\0\0\0','\2\0\0\0') == -1)
  assert(luasodium.is_zero('\0\0\0\0') == true)
  assert(luasodium.is_zero('\1\0\0\1') == false)
end

do
  local original = '\1\2\3\4\5\6\7'
  local padded = luasodium.pad(original,8)
  assert(string.len(padded) == 8)
  local res = luasodium.unpad(padded,8)
  assert(res == original)
end
end

print('success')
