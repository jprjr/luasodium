local modules = {
  'crypto_auth',
  'crypto_box',
  'crypto_generichash',
  'crypto_hash',
  'crypto_onetimeauth',
  'crypto_scalarmult',
  'crypto_secretbox',
  'crypto_secretstream',
  'crypto_shorthash',
  'crypto_sign',
  'crypto_stream',
  'crypto_verify',
  'randombytes',
  'utils',
  'version',
}

return function(t)
  local M = {}

  for _,m in ipairs(modules) do
    local mod = require(string.format('luasodium.%s.%s',
      m,t))
    for k,v in pairs(mod) do
      M[k] = v
    end
  end

  return M
end
