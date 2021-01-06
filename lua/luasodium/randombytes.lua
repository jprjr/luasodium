local ok, mod

ok, mod = pcall(require,'luasodium.randombytes.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.randombytes.core')
if ok then
  return mod
end

return require'luasodium.randombytes.pureffi'
