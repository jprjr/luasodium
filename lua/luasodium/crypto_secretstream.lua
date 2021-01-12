local ok, mod

ok, mod = pcall(require,'luasodium.crypto_secretstream.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_secretstream.core')
if ok then
  return mod
end

return require'luasodium.crypto_secretstream.pureffi'


