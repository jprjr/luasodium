local lib = require'luasodium'

for i=1,10000 do

do
  local hash = lib.crypto_hash('a message')
  assert(string.len(hash) == lib.crypto_hash_BYTES)
end

end

print('success')
