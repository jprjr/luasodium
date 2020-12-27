do
    require('luasodium').init()
end

local crypto_box = require'luasodium.crypto_box'

print('success')
