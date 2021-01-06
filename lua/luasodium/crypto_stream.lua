local ok, mod

ok, mod = pcall(require,'luasodium.crypto_stream.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_stream.core')
if ok then
  return mod
end

return require'luasodium.crypto_stream.pureffi'

