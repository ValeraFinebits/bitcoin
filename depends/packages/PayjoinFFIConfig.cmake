include(CMakeFindDependencyMacro)
find_dependency(Threads)

get_filename_component(
  _payjoin_ffi_prefix
  "${CMAKE_CURRENT_LIST_DIR}/../../.."
  ABSOLUTE
)

set(_payjoin_ffi_library
  "${_payjoin_ffi_prefix}/lib/libpayjoin_ffi.a"
)

set(_payjoin_ffi_cpp_directory
  "${_payjoin_ffi_prefix}/share/payjoin/cpp"
)
set(_payjoin_ffi_cpp_source
  "${_payjoin_ffi_cpp_directory}/payjoin.cpp"
)
set(_payjoin_ffi_cpp_header
  "${_payjoin_ffi_cpp_directory}/payjoin.hpp"
)
set(_payjoin_ffi_cpp_scaffolding
  "${_payjoin_ffi_cpp_directory}/payjoin_scaffolding.hpp"
)

if(NOT EXISTS "${_payjoin_ffi_library}"
   OR NOT EXISTS "${_payjoin_ffi_cpp_source}"
   OR NOT EXISTS "${_payjoin_ffi_cpp_header}"
   OR NOT EXISTS "${_payjoin_ffi_cpp_scaffolding}"
)
  set(PayjoinFFI_FOUND FALSE)
  set(PayjoinFFI_NOT_FOUND_MESSAGE
    "Payjoin FFI package is incomplete; expected Rust library and C++ bindings under ${_payjoin_ffi_prefix}"
  )
  unset(_payjoin_ffi_library)
  unset(_payjoin_ffi_cpp_directory)
  unset(_payjoin_ffi_cpp_source)
  unset(_payjoin_ffi_cpp_header)
  unset(_payjoin_ffi_cpp_scaffolding)
  unset(_payjoin_ffi_prefix)
  return()
endif()

if(NOT TARGET Payjoin::ffi)
  add_library(Payjoin::ffi STATIC IMPORTED)
  set_target_properties(Payjoin::ffi PROPERTIES
    IMPORTED_LOCATION "${_payjoin_ffi_library}"
    INTERFACE_LINK_LIBRARIES "Threads::Threads;${CMAKE_DL_LIBS};m;rt;util"
  )
endif()

if(NOT TARGET Payjoin::cpp)
  add_library(Payjoin::cpp INTERFACE IMPORTED)
  set_target_properties(Payjoin::cpp PROPERTIES
    INTERFACE_SOURCES "${_payjoin_ffi_cpp_source}"
    INTERFACE_INCLUDE_DIRECTORIES "${_payjoin_ffi_cpp_directory}"
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_payjoin_ffi_cpp_directory}"
    INTERFACE_LINK_LIBRARIES Payjoin::ffi
  )
endif()

set(PayjoinFFI_FOUND TRUE)
unset(_payjoin_ffi_library)
unset(_payjoin_ffi_cpp_directory)
unset(_payjoin_ffi_cpp_source)
unset(_payjoin_ffi_cpp_header)
unset(_payjoin_ffi_cpp_scaffolding)
unset(_payjoin_ffi_prefix)
