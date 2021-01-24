local ok, mod

ok, mod = pcall(require,'luasodium.crypto_pwhash.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_pwhash.core')
if ok then
  return mod
end

return require'luasodium.crypto_pwhash.pureffi'




