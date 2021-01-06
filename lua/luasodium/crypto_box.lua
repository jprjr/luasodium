local ok, mod

ok, mod = pcall(require,'luasodium.crypto_box.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_box.core')
if ok then
  return mod
end

return require'luasodium.crypto_box.pureffi'
