local lib = require'luasodium.crypto_onetimeauth'

local premade_key = {
  83, 21, 59, 40, 150, 103, 152, 168,
  130, 18, 221, 36, 241, 86, 169, 91,
  85, 174, 114, 181, 18, 171, 243, 28,
  6, 19, 73, 97, 201, 154, 165, 112,
}

local expected_auth = {
  16, 113, 131, 16, 241, 219, 80, 253,
  90, 136, 14, 219, 255, 174, 234, 189,
}

local key_bytes = {}
for i,v in ipairs(premade_key) do
  key_bytes[i] = string.char(v)
end

local key = table.concat(key_bytes,'')
local message = 'a message'

for i=1,1000 do

do
  local auth = lib.crypto_onetimeauth(message,key)
  assert(string.len(auth) == lib.crypto_onetimeauth_BYTES)
  for i=1,lib.crypto_onetimeauth_BYTES do
    assert(string.byte(auth,i) == expected_auth[i])
  end
end

do
  local state = lib.crypto_onetimeauth_init(key)
  assert(lib.crypto_onetimeauth_update(state,message) == true)
  local auth = lib.crypto_onetimeauth_final(state)

  for i=1,lib.crypto_onetimeauth_BYTES do
    assert(string.byte(auth,i) == expected_auth[i])
  end

  local state2 = lib.crypto_onetimeauth_init(key)
  assert(state2:update(message) == true)
  assert(state2:final() == auth)
end

end

print('success')


