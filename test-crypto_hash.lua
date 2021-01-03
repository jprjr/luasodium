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

end

print('success')
