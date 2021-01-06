local ok, lib

ok, lib = pcall(require,'luasodium.ffi')
if ok then
  return lib
end

ok, lib = pcall(require,'luasodium.core')
if ok then
  return lib
end

return require'luasodium.pureffi'
