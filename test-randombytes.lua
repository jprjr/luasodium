local lib = require'luasodium.randombytes'

for i=1,100 do

do
  local r = lib.randombytes_random()
  local seed = string.rep('\0',lib.randombytes_SEEDBYTES)
  assert(type(r) == 'number')
  assert(lib.randombytes_uniform(1) == 0)
  assert(string.len(lib.randombytes_buf(10)) == 10)
  local result = lib.randombytes_buf_deterministic(10,seed)
  local result_vals = {
    161,
    31,
    143,
    18,
    208,
    135,
    111,
    115,
    109,
    45,
  }

  for i=1,10 do
    assert(string.byte(result,i) == result_vals[i])
  end
  lib.randombytes_stir()
end

end

lib.randombytes_close()

print('success')
