local ok, mod = pcall(require,'luasodium.crypto_stream.ffi')
if ok then
  return mod
end

return require'luasodium.crypto_stream.core'

