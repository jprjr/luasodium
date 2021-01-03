local lib = require'luasodium.version'

assert(type(lib._VERSION) == 'string')
assert(type(lib.sodium_version_string()) == 'string')
assert(type(lib.sodium_library_version_major()) == 'number')
assert(type(lib.sodium_library_version_minor()) == 'number')
assert(type(lib.sodium_library_minimal()) == 'number')

for _,v in ipairs({
  '_VERSION',
  'sodium_version_string',
  'sodium_library_version_major',
  'sodium_library_version_minor',
  'sodium_library_minimal'}) do
  print(v,type(lib[v]) == 'function' and lib[v]() or lib[v])
end

print('success')
