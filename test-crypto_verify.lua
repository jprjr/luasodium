local lib = require'luasodium.crypto_verify'

local test1_16 = string.rep('\0',16)
local test2_16 = string.rep('\0',16)
local test3_16 = string.rep('\1',16)

local test1_32 = string.rep('\0',32)
local test2_32 = string.rep('\0',32)
local test3_32 = string.rep('\1',32)

local test1_24 = string.rep('\0',24)
local test2_24 = string.rep('\0',24)
local test3_24 = string.rep('\1',24)

for i=1,1000 do

do
  assert(lib.crypto_verify_16(test1_16,test2_16) == true)
  assert(lib.crypto_verify_16(test1_16,test3_16) == false)

  assert(lib.crypto_verify_32(test1_32,test2_32) == true)
  assert(lib.crypto_verify_32(test1_32,test3_32) == false)

  assert(pcall(lib.crypto_verify_16,test1_24,test2_24) == false)
end

end

print('success')
