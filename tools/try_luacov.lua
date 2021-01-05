local ok, luacov = pcall(require,'luacov.runner')
if ok then
  luacov()
  --table.insert(luacov.configuration.exclude, 'busted_bootstrap$')
  --table.insert(luacov.configuration.exclude, 'busted/')
  --table.insert(luacov.configuration.exclude, 'luassert/')
  --table.insert(luacov.configuration.exclude, 'say/')
  --table.insert(luacov.configuration.exclude, 'pl/')
  --table.insert(luacov.configuration.exclude, 'cliargs/')
  --table.insert(luacov.configuration.exclude, 'moonscript/')
  --table.insert(luacov.configuration.exclude, 'mediator$')
  --table.insert(luacov.configuration.exclude, 'system/')
  --table.insert(luacov.configuration.exclude, 'term/')
  table.insert(luacov.configuration.include, 'luasodium$')
  table.insert(luacov.configuration.include, 'luasodium%/.+$')
end