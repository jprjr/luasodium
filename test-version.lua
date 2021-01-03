local lib = require'luasodium.version'

assert(type(lib._VERSION) == 'string')
print('success')
