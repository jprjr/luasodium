cmake_minimum_required(VERSION 3.1)
project(luasodium)

set(LUASODIUM_MODULES
  crypto_auth
  crypto_box
  crypto_hash
  crypto_onetimeauth
  crypto_scalarmult
  crypto_secretbox
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

option(BUILD_SHARED_LIBS "Build modules as shared libraries" ON)

find_package(PkgConfig)
pkg_check_modules(LIBSODIUM libsodium)
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
  libsodium
  DEFAULT_MSG
  LIBSODIUM_LIBRARIES
  LIBSODIUM_INCLUDEDIR
)

if(NOT LIBSODIUM_INCLUDEDIR)
    message(FATAL_ERROR "Unable to find libsodium, please set LIBSODIUM_INCLUDEDIR and LIBSODIUM_LIBRARIES")
endif()

if(NOT LUA_INCLUDE_DIR)
    if(LUA_VERSION)
      find_package(Lua ${LUA_VERSION} EXACT REQUIRED)
    else()
      find_package(Lua REQUIRED)
    endif()
endif()

set(CMODULE_INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
set(LUAMODULE_INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")

set(bin2c_cmdline_ffi_default_signatures
  "-DOUTPUT_C=${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/ffi-default-signatures.h"
  "-DINPUT_FILE=${CMAKE_CURRENT_SOURCE_DIR}/ffi/luasodium/_ffi/default_signatures.lua"
  "-DIDENT=ffi_default_signatures"
  -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/bin2c.cmake"
)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/ffi-default-signatures.h"
  COMMAND ${CMAKE_COMMAND} ARGS ${bin2c_cmdline_ffi_default_signatures}
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/ffi/luasodium/_ffi/default_signatures.lua"
  COMMENT "Running bin2c"
  PRE_BUILD VERBATIM
)

set(bin2c_cmdline_ffi_function_loader
  "-DOUTPUT_C=${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/ffi-function-loader.h"
  "-DINPUT_FILE=${CMAKE_CURRENT_SOURCE_DIR}/ffi/luasodium/_ffi/function_loader.lua"
  "-DIDENT=ffi_function_loader"
  -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/bin2c.cmake"
)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/ffi-function-loader.h"
  COMMAND ${CMAKE_COMMAND} ARGS ${bin2c_cmdline_ffi_function_loader}
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/ffi/luasodium/_ffi/function_loader.lua"
  COMMENT "Running bin2c"
  PRE_BUILD VERBATIM
)

foreach(LS_MOD ${LUASODIUM_MODULES})
  set(bin2c_${LS_MOD}_ffi_signatures
    "-DOUTPUT_C=${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/${LS_MOD}/ffi-signatures.h"
    "-DINPUT_FILE=${CMAKE_CURRENT_SOURCE_DIR}/ffi/luasodium/${LS_MOD}/signatures.lua"
    "-DIDENT=ls_${LS_MOD}_ffi_signatures"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/bin2c.cmake"
  )
  add_custom_command(
    OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/${LS_MOD}/ffi-signatures.h"
    COMMAND ${CMAKE_COMMAND} ARGS ${bin2c_${LS_MOD}_ffi_signatures}
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/ffi/luasodium/${LS_MOD}/signatures.lua"
    COMMENT "Running bin2c"
    PRE_BUILD VERBATIM
  )
  set(bin2c_${LS_MOD}_ffi_implementation
    "-DOUTPUT_C=${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/${LS_MOD}/ffi-implementation.h"
    "-DINPUT_FILE=${CMAKE_CURRENT_SOURCE_DIR}/ffi/luasodium/${LS_MOD}/implementation.lua"
    "-DIDENT=ls_${LS_MOD}_ffi_implementation"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/bin2c.cmake"
  )
  add_custom_command(
    OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/${LS_MOD}/ffi-implementation.h"
    COMMAND ${CMAKE_COMMAND} ARGS ${bin2c_${LS_MOD}_ffi_implementation}
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/ffi/luasodium/${LS_MOD}/implementation.lua"
    COMMENT "Running bin2c"
    PRE_BUILD VERBATIM
  )
  install(FILES "lua/luasodium/${LS_MOD}.lua"
    DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}/luasodium/"
  )
endforeach()

foreach(LS_CT ${LUASODIUM_CORETYPES})
  add_library("${LS_CT}" "c/luasodium/${LS_CT}.c")
  target_link_libraries("${LS_CT}" ${LIBSODIUM_LIBRARIES})
  target_sources("${LS_CT}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/ffi-default-signatures.h")
  target_sources("${LS_CT}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/ffi-function-loader.h")

  target_include_directories("${LS_CT}" PRIVATE ${LUA_INCLUDE_DIR})
  target_include_directories("${LS_CT}" PRIVATE ${LIBSODIUM_INCLUDE_DIR})

  set_target_properties("${LS_CT}" PROPERTIES PREFIX "")
  set_target_properties("${LS_CT}" PROPERTIES OUTPUT_NAME "${LS_CT}")
  set_target_properties("${LS_CT}" PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/luasodium")
  set_target_properties("${LS_CT}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/luasodium")
  set_target_properties("${LS_CT}" PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/luasodium")

  install(TARGETS "${LS_CT}"
      LIBRARY DESTINATION "${CMODULE_INSTALL_LIB_DIR}/luasodium"
      RUNTIME DESTINATION "${CMODULE_INSTALL_LIB_DIR}/luasodium"
      ARCHIVE DESTINATION "${CMODULE_INSTALL_LIB_DIR}/luasodium"
  )

  foreach(LS_MOD ${LUASODIUM_MODULES})
    add_library("${LS_MOD}_${LS_CT}" "c/luasodium/${LS_MOD}/${LS_CT}.c")
    target_link_libraries("${LS_MOD}_${LS_CT}" ${LIBSODIUM_LIBRARIES})
    target_include_directories("${LS_MOD}_${LS_CT}" PRIVATE ${LUA_INCLUDE_DIR})
    target_include_directories("${LS_MOD}_${LS_CT}" PRIVATE ${LIBSODIUM_INCLUDE_DIR})
    target_sources("${LS_MOD}_${LS_CT}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/ffi-default-signatures.h")
    target_sources("${LS_MOD}_${LS_CT}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/ffi-function-loader.h")
    target_sources("${LS_MOD}_${LS_CT}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/${LS_MOD}/ffi-signatures.h")
    target_sources("${LS_MOD}_${LS_CT}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/${LS_MOD}/ffi-implementation.h")
    target_sources("${LS_CT}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/${LS_MOD}/ffi-signatures.h")
    target_sources("${LS_CT}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/luasodium/${LS_MOD}/ffi-implementation.h")

    set_target_properties("${LS_MOD}_${LS_CT}" PROPERTIES PREFIX "")
    set_target_properties("${LS_MOD}_${LS_CT}" PROPERTIES OUTPUT_NAME "${LS_CT}")
    set_target_properties("${LS_MOD}_${LS_CT}" PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/luasodium/${LS_MOD}")
    set_target_properties("${LS_MOD}_${LS_CT}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/luasodium/${LS_MOD}")
    set_target_properties("${LS_MOD}_${LS_CT}" PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/luasodium/${LS_MOD}")
    install(TARGETS "${LS_MOD}_${LS_CT}"
      LIBRARY DESTINATION "${CMODULE_INSTALL_LIB_DIR}/luasodium/${LS_MOD}"
      RUNTIME DESTINATION "${CMODULE_INSTALL_LIB_DIR}/luasodium/${LS_MOD}"
      ARCHIVE DESTINATION "${CMODULE_INSTALL_LIB_DIR}/luasodium/${LS_MOD}"
    )
  endforeach()
endforeach()


install(FILES "lua/luasodium.lua"
  DESTINATION "${LUAMODULE_INSTALL_LIB_DIR}"
)


