local lib = require'luasodium'

local expected = {
  36, 166, 137, 74, 84, 118, 157, 225,
  136, 104, 231, 95, 232, 156, 215, 110,
  24, 95, 206, 127, 136, 148, 76, 35,
  192, 230, 240, 71, 202, 197, 133, 26,
}

for i=1,10000 do

do
  local key = string.rep('\0',lib.crypto_auth_KEYBYTES)
  local tag = lib.crypto_auth('a message',key)
  assert(string.len(tag) == lib.crypto_auth_BYTES)

  for j=1,string.len(tag) do
    assert(string.byte(tag,j) == expected[j])
  end
end

do
  local key = lib.crypto_auth_keygen()
  assert(string.len(key) == lib.crypto_auth_KEYBYTES)
  local tag = lib.crypto_auth('a message',key)
  assert(string.len(tag) == lib.crypto_auth_BYTES)
  assert(lib.crypto_auth_verify(tag,'a message',key) == true)
  assert(lib.crypto_auth_verify(tag,'another message',key) == false)
end


end

print('success')
