local mods = {...}

local luasodium = require'luasodium'

for _,m in ipairs(mods) do
  local mod = require('luasodium.' .. m)
  for k in pairs(mod) do
    assert(luasodium[k] ~= nil)
  end
end
