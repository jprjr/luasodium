local ok, mod

ok, mod = pcall(require,'luasodium.utils.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.utils.core')
if ok then
  return mod
end

return require'luasodium.utils.pureffi'
