local lib = require'luasodium.crypto_hash'

for i=1,10000 do

do
  local hash = lib.crypto_hash('a message')
  assert(string.len(hash) == lib.crypto_hash_BYTES)
end

do
  local hash = lib.crypto_hash_sha256('a message')
  assert(string.len(hash) == lib.crypto_hash_sha256_BYTES)
end

do
  local hash = lib.crypto_hash_sha512('a message')
  assert(string.len(hash) == lib.crypto_hash_sha512_BYTES)
end

do
  local state = lib.crypto_hash_sha256_init()
  assert(lib.crypto_hash_sha256_update(state,'a message') == true)
  assert(lib.crypto_hash_sha256_final(state) == lib.crypto_hash_sha256('a message'))
end

do
  local state = lib.crypto_hash_sha512_init()
  assert(lib.crypto_hash_sha512_update(state,'a message') == true)
  assert(lib.crypto_hash_sha512_final(state) == lib.crypto_hash_sha512('a message'))
end

do
  local state = lib.crypto_hash_sha256_init()
  assert(state:update('a message') == true)
  assert(state:final() == lib.crypto_hash_sha256('a message'))
end

do
  local state = lib.crypto_hash_sha512_init()
  assert(state:update('a message') == true)
  assert(state:final() == lib.crypto_hash_sha512('a message'))
end

end

print('success')
