local lib = require'luasodium.version'

if jit then
  assert(lib == require'luasodium.version.ffi')
end

assert(type(lib._VERSION) == 'string')
print('success')
