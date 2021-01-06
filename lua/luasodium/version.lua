local ok, mod

ok, mod = pcall(require,'luasodium.version.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.version.core')
if ok then
  return mod
end

return require'luasodium.version.pureffi'
