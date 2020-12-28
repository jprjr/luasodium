do
    require('luasodium').init()
end

local crypto_box = require'luasodium.crypto_box'

do
  local pk, sk = crypto_box.keypair()
  assert(string.len(pk) == crypto_box.PUBLICKEYBYTES)
  assert(string.len(sk) == crypto_box.SECRETKEYBYTES)
end

print('success')
