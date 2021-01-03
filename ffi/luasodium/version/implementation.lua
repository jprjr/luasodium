local _VERSION = '1.0.1'

return function(libs)
  local M = {
    _VERSION = _VERSION
  }

  -- this may be running from my generic 'show version' script
  -- *or* from the regular C API. if libs is empty, we're not in
  -- an FFI environment, so return.
  if not libs then return M end

  local ffi = require'ffi'

  local function ls_sodium_version_string()
    return ffi.string(libs.sodium.sodium_version_string())
  end

  local function ls_sodium_library_version_major()
    return tonumber(libs.sodium.sodium_library_version_major())
  end

  local function ls_sodium_library_version_minor()
    return tonumber(libs.sodium.sodium_library_version_minor())
  end

  local function ls_sodium_library_minimal()
    return tonumber(libs.sodium.sodium_library_minimal())
  end

  M.sodium_version_string = ls_sodium_version_string
  M.sodium_library_version_major = ls_sodium_library_version_major
  M.sodium_library_version_minor = ls_sodium_library_version_minor
  M.sodium_library_minimal = ls_sodium_library_minimal

  return M
end
