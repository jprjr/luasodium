local M = {}

local modules = {
  'crypto_auth',
  'crypto_box',
  'crypto_hash',
  'crypto_onetimeauth',
  'crypto_scalarmult',
  'crypto_secretbox',
  'crypto_sign',
  'crypto_stream',
  'crypto_verify',
  'randombytes',
  'utils',
  'version',
}

for _,m in ipairs(modules) do
  local mod = require('luasodium.' .. m)
  for k,v in pairs(mod) do
    M[k] = v
  end
end


return M
