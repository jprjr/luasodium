do
    require('luasodium').init()
end

local randombytes = require'luasodium.randombytes'

for i=1,100 do

do
  local r = randombytes.random()
  local seed = string.rep('\0',randombytes.SEEDBYTES)
  assert(type(r) == 'number')
  assert(randombytes.uniform(1) == 0)
  assert(string.len(randombytes.buf(10)) == 10)
  local result = randombytes.buf_deterministic(10,seed)
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
  randombytes.stir()
end

end

randombytes.close()

print('success')
