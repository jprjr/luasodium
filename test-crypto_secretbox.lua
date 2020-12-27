do
    require('luasodium').init()
end

local crypto_secretbox = require'luasodium.crypto_secretbox'

local nonce = string.rep('\0',crypto_secretbox.NONCEBYTES)
local key = string.rep('\0',crypto_secretbox.KEYBYTES)

for i=1,10000 do

do
  local encrypted = crypto_secretbox.easy('yay',nonce,key)
  assert(string.len(encrypted) == 19)
  local result = {
    84,
    131,
    248,
    12,
    139,
    116,
    241,
    128,
    234,
    239,
    195,
    4,
    159,
    62,
    44,
    3,
    191,
    95,
    194,
  }
  for i=1,#encrypted do
    assert(string.byte(encrypted,i) == result[i])
  end
  assert(crypto_secretbox.open_easy(encrypted,nonce,key) == 'yay')
end

do
  local encrypted, mac = crypto_secretbox.detached('yay',nonce,key)
  assert(string.len(encrypted) == 3)
  local mac_result = {
    84,
    131,
    248,
    12,
    139,
    116,
    241,
    128,
    234,
    239,
    195,
    4,
    159,
    62,
    44,
    3,
  }
  local enc_result = {
    191,
    95,
    194,
  }
  for i=1,#mac do
    assert(string.byte(mac,i) == mac_result[i])
  end
  for i=1,#encrypted do
    assert(string.byte(encrypted,i) == enc_result[i])
  end

  assert(crypto_secretbox.open_detached(encrypted,mac,nonce,key) == 'yay')
end

do
  assert(string.len(crypto_secretbox.keygen()) == crypto_secretbox.KEYBYTES)
end

end

print('success')
