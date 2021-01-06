local signatures = {
  ['sodium_version_string'] = [[
     const char * %s(void)
  ]],
  ['sodium_library_version_major'] = [[
     int %s(void)
  ]],
  ['sodium_library_version_minor'] = [[
     int %s(void)
  ]],
  ['sodium_library_minimal'] = [[
     int %s(void)
  ]],
}

return signatures
