local lib = require'luasodium.crypto_box'

if jit then
  assert(lib == require'luasodium.crypto_box.ffi')
end

for i=1,10000 do

do
  local pk, sk = lib.crypto_box_keypair()
  assert(string.len(pk) == lib.crypto_box_PUBLICKEYBYTES)
  assert(string.len(sk) == lib.crypto_box_SECRETKEYBYTES)
end

do
  local seed = string.rep('\0',lib.crypto_box_SEEDBYTES)
  local pk, sk = lib.crypto_box_seed_keypair(seed)
  assert(string.len(pk) == lib.crypto_box_PUBLICKEYBYTES)
  assert(string.len(sk) == lib.crypto_box_SECRETKEYBYTES)

  local expected_pk = {
    91, 245, 92, 115, 184, 46, 190, 34,
    190, 128, 243, 67, 6, 103, 175, 87,
    15, 174, 37, 86, 166, 65, 94, 107,
    48, 212, 6, 83, 0, 170, 148, 125,
  }

  local expected_sk = {
    80, 70, 173, 193, 219, 168, 56, 134,
    123, 43, 187, 253, 208, 195, 66, 62,
    88, 181, 121, 112, 181, 38, 122, 144,
    245, 121, 96, 146, 74, 135, 241, 150,
  }

  for i=1,string.len(pk) do
    assert(string.byte(pk,i) == expected_pk[i])
  end

  for i=1,string.len(sk) do
    assert(string.byte(sk,i) == expected_sk[i])
  end
end

local sender_seed   = string.rep(string.char(0)  ,lib.crypto_box_SEEDBYTES)
local receiver_seed = string.rep(string.char(255),lib.crypto_box_SEEDBYTES)
local nonce = string.rep(string.char(0),lib.crypto_box_NONCEBYTES)
local sender_pk, sender_sk = lib.crypto_box_seed_keypair(sender_seed)
local receiver_pk, receiver_sk = lib.crypto_box_seed_keypair(receiver_seed)

do
  local message = 'hello there'
  local encrypted = lib.crypto_box_easy(message,nonce,receiver_pk,sender_sk)
  local decrypted = lib.crypto_box_open_easy(encrypted,nonce,sender_pk,receiver_sk)
  assert(decrypted == message)
  assert(lib.crypto_box(message,nonce,receiver_pk,sender_sk) == encrypted)
  assert(lib.crypto_box_open(encrypted,nonce,sender_pk,receiver_sk) == message)
end

do
  local message = 'hello there detached'
  local encrypted, mac = lib.crypto_box_detached(message,nonce,receiver_pk,sender_sk)
  local decrypted = lib.crypto_box_open_detached(encrypted,mac,nonce,sender_pk,receiver_sk)
  assert(decrypted == message)
end

do
  local message, k, ok, encrypted, decrypted, mac
  message = 'hello there'
  k = lib.crypto_box_beforenm(receiver_pk,sender_sk)
  ok = lib.crypto_box_beforenm(sender_pk,receiver_sk)

  encrypted = lib.crypto_box_easy_afternm(message,nonce,k)
  decrypted = lib.crypto_box_open_easy(encrypted,nonce,sender_pk,receiver_sk)
  assert(decrypted == message)

  decrypted = lib.crypto_box_open_easy_afternm(encrypted,nonce,k)
  assert(decrypted == message)

  decrypted = lib.crypto_box_open_easy_afternm(encrypted,nonce,ok)
  assert(decrypted == message)

  encrypted, mac = lib.crypto_box_detached_afternm(message,nonce,k)

  decrypted = lib.crypto_box_open_detached(encrypted,mac,nonce,sender_pk,receiver_sk)
  assert(decrypted == message)

  decrypted = lib.crypto_box_open_detached_afternm(encrypted,mac,nonce,ok)
  assert(decrypted == message)

end

end

print('success')
