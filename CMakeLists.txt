cmake_minimum_required(VERSION 3.1)
project(luasodium)

# set to whatever modules we're building
set(LUASODIUM_MODULES
  crypto_aead
  crypto_auth
  crypto_box
  crypto_generichash
  crypto_hash
  crypto_onetimeauth
  crypto_pwhash
  crypto_scalarmult
  crypto_secretbox
  crypto_secretstream
  crypto_shorthash
  crypto_sign
  crypto_stream
  crypto_verify
  randombytes
  utils
  version
)

set(LUASODIUM_CORETYPES
  core
  ffi
)

set(LUASODIUM_ROOTMODULES
  _all
  core
  ffi
  pureffi
)

set(LUASODIUM_FFIMODULES
  constant_loader
  default_signatures
  ffi_loader
  function_loader
  lib_loader
  pureffi_loader
)

# by default we probably want shared libraries, set this
# to off if you want to build static binaries with this library.
option(BUILD_SHARED_LIBS "Build modules as shared libraries" ON)

if(NOT LUASODIUM_VERSION)
  find_package(Git)
  if(GIT_FOUND)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0
      RESULT_VARIABLE VERSION_RESULT
      OUTPUT_VARIABLE LUASODIUM_VERSION)
  else()
    set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})
    include(LuasodiumVersion)
  endif()
endif()

string(REGEX REPLACE "v?([0-9]+)\\..*" "\\1" LUASODIUM_VERSION_MAJOR "${LUASODIUM_VERSION}")
string(REGEX REPLACE "v?[0-9]+\\.([0-9])+.*" "\\1" LUASODIUM_VERSION_MINOR "${LUASODIUM_VERSION}")
string(REGEX REPLACE "v?[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" LUASODIUM_VERSION_PATCH "${LUASODIUM_VERSION}")

# try to find libsodium via pkg-config
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(LIBSODIUM libsodium)
endif()

if(NOT LIBSODIUM_LIBRARIES)
  # try finding the vcpkg version of sodium (windows)
  find_package(unofficial-sodium)
  if(unofficial-sodium_FOUND)
  set(LIBSODIUM_LIBRARIES unofficial-sodium::sodium)
  endif()
endif()

if(NOT LIBSODIUM_LIBRARIES)
  message(FATAL_ERROR "Unable to find libsodium, please set LIBSODIUM_INCLUDEDIR and LIBSODIUM_LIBRARIES")
endif()

# if a user gives us a LUA_INCLUDE_DIR, just use that
if(NOT LUA_INCLUDE_DIR)
  if(LUA_VERSION)
    find_package(Lua ${LUA_VERSION} EXACT REQUIRED)
  else()
    find_package(Lua REQUIRED)
    set(LUA_VERSION "${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}" CACHE STRING "Lua version to use")
  endif()
endif()

# TODO: check if the include_dir is given and get the lua version that way
if(NOT LUA_VERSION)
  message(FATAL_ERROR "Unable to determine lua version, please set LUA_VERSION")
endif()

if(NOT CMAKE_CROSSCOMPILING)
  enable_testing()

  add_executable(ls_test_spec test/test.c)
  target_link_libraries(ls_test_spec PRIVATE ${LUA_LIBRARIES})
  target_include_directories(ls_test_spec PRIVATE ${LUA_INCLUDE_DIR})
endif()

set(CMODULE_INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib/lua/${LUA_VERSION}")
set(LUAMODULE_INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/lua/${LUA_VERSION}")

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/version/constants.h")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/version/constants.h.in"
    "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/version/constants.h"
    @ONLY
  )
endif()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/lua/luasodium/version/implementation.lua")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/luasodium/version/implementation.lua.in"
    "${CMAKE_CURRENT_SOURCE_DIR}/lua/luasodium/version/implementation.lua"
    @ONLY
  )
endif()

configure_file(
  "lua/luasodium.lua"
  "${CMAKE_BINARY_DIR}/luasodium.lua"
  COPYONLY
)

install(FILES "lua/luasodium.lua"
  DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/"
)

foreach(LUAFILE ${LUASODIUM_ROOTMODULES})
  configure_file(
    "lua/luasodium/${LUAFILE}.lua"
    "${CMAKE_BINARY_DIR}/luasodium/${LUAFILE}.lua"
    COPYONLY
  )

  install(FILES "lua/luasodium/${LUAFILE}.lua"
    DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/luasodium/"
  )
endforeach()

foreach(LUAFILE ${LUASODIUM_FFIMODULES})
  configure_file(
    "lua/luasodium/_ffi/${LUAFILE}.lua"
    "${CMAKE_BINARY_DIR}/luasodium/_ffi/${LUAFILE}.lua"
    COPYONLY
  )

  install(FILES "lua/luasodium/_ffi/${LUAFILE}.lua"
    DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/luasodium/_ffi/"
  )
endforeach()

foreach(LS_MOD ${LUASODIUM_MODULES})
  configure_file(
  "lua/luasodium/${LS_MOD}.lua"
  "${CMAKE_BINARY_DIR}/luasodium/${LS_MOD}.lua"
  COPYONLY
  )

  configure_file(
  "lua/luasodium/${LS_MOD}/constants.lua"
  "${CMAKE_BINARY_DIR}/luasodium/${LS_MOD}/constants.lua"
  COPYONLY
  )

  configure_file(
  "lua/luasodium/${LS_MOD}/implementation.lua"
  "${CMAKE_BINARY_DIR}/luasodium/${LS_MOD}/implementation.lua"
  COPYONLY
  )

  configure_file(
  "lua/luasodium/${LS_MOD}/pureffi.lua"
  "${CMAKE_BINARY_DIR}/luasodium/${LS_MOD}/pureffi.lua"
  COPYONLY
  )

  configure_file(
  "lua/luasodium/${LS_MOD}/signatures.lua"
  "${CMAKE_BINARY_DIR}/luasodium/${LS_MOD}/signatures.lua"
  COPYONLY
  )

  install(FILES "lua/luasodium/${LS_MOD}.lua"
  DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/luasodium/"
  )

  install(FILES "lua/luasodium/${LS_MOD}/constants.lua"
  DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/luasodium/${LS_MOD}/"
  )

  install(FILES "lua/luasodium/${LS_MOD}/implementation.lua"
  DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/luasodium/${LS_MOD}/"
  )

  install(FILES "lua/luasodium/${LS_MOD}/pureffi.lua"
  DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/luasodium/${LS_MOD}/"
  )

  install(FILES "lua/luasodium/${LS_MOD}/signatures.lua"
  DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/luasodium/${LS_MOD}/"
  )

  if(NOT CMAKE_CROSSCOMPILING)
    add_test(NAME "${LS_MOD}_tests" COMMAND ls_test_spec "${CMAKE_SOURCE_DIR}/spec/${LS_MOD}_spec.lua")
  endif()

endforeach()

set(luasodium_sources "c/luasodium/luasodium.c")

foreach(LS_CT ${LUASODIUM_CORETYPES})
  foreach(LS_MOD ${LUASODIUM_MODULES})
    list(APPEND luasodium_sources "c/luasodium/${LS_MOD}/${LS_CT}.c")
  endforeach()
endforeach()

add_library(luasodium ${luasodium_sources})

target_link_libraries(luasodium PRIVATE ${LIBSODIUM_LIBRARIES})
target_link_directories(luasodium PRIVATE ${LIBSODIUM_LIBRARY_DIRS})
if(WIN32)
  target_link_libraries(luasodium PRIVATE ${LUA_LIBRARIES})
endif()
target_include_directories(luasodium PRIVATE ${LUA_INCLUDE_DIR})
target_include_directories(luasodium PRIVATE ${LIBSODIUM_INCLUDEDIR})

if(APPLE)
  set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup")
  if(BUILD_SHARED_LIBS)
    set_target_properties(luasodium PROPERTIES SUFFIX ".so")
  endif()
endif()

set_target_properties(luasodium PROPERTIES PREFIX "")
set_target_properties(luasodium PROPERTIES OUTPUT_NAME "luasodium")
set_target_properties(luasodium PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set_target_properties(luasodium PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set_target_properties(luasodium PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
  string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
  set_target_properties(luasodium PROPERTIES RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}")
  set_target_properties(luasodium PROPERTIES LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}")
  set_target_properties(luasodium PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}")
endforeach()

install(TARGETS luasodium
  LIBRARY DESTINATION "${CMODULE_INSTALL_LIB_DIR}"
  RUNTIME DESTINATION "${CMODULE_INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${CMODULE_INSTALL_LIB_DIR}"
)
