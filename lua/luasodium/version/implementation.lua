local _VERSION_MAJOR = 1
local _VERSION_MINOR = 2
local _VERSION_PATCH = 0

local _VERSION = string.format('%d.%d.%d',
  _VERSION_MAJOR,
  _VERSION_MINOR,
  _VERSION_PATCH)

return function(libs)
  local M = {
    _VERSION = _VERSION,
    _VERSION_MAJOR = _VERSION_MAJOR,
    _VERSION_MINOR = _VERSION_MINOR,
    _VERSION_PATCH = _VERSION_PATCH,
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
