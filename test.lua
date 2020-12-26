local inspect = require'inspect'

local luasodium   = require'luasodium'
local randombytes = require'luasodium.randombytes'

print(inspect(luasodium))
print(inspect(randombytes))

-- https://libsodium.gitbook.io/doc/usage
assert(luasodium.init())

-- https://libsodium.gitbook.io/doc/helpers
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

do
  local r = randombytes.random()
  local seed = string.rep('\0',randombytes.SEEDBYTES)
  assert(type(r) == 'number')
  assert(randombytes.uniform(1) == 0)
  assert(string.len(randombytes.buf(10)) == 10)
  local result = randombytes.buf_deterministic(10,seed)
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
  randombytes.stir()
  randombytes.close()
end
