local lib = require'luasodium.crypto_stream'

local nonce = string.rep('\0',lib.crypto_stream_NONCEBYTES)
local key = string.rep('\0',lib.crypto_stream_KEYBYTES)

local expected_str = {
  186, 110, 38, 223, 75, 46, 162, 207,
  100, 210, 211, 99, 102, 35, 181, 244,
}

for i=1,1000 do

do
  local str = lib.crypto_stream(16,nonce,key)
  assert(string.len(str) == 16)
  for i=1,16 do
    assert(expected_str[i] == string.byte(str,i))
  end

  local x = lib.crypto_stream_xor('message',nonce,key)
  assert(string.len(x) == string.len('message'))
  assert(lib.crypto_stream_xor(x,nonce,key) == 'message')
end

end

print('success')
