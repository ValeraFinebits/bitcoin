# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

find_package(PayjoinFFI CONFIG REQUIRED)

add_library(bitcoin_payjoin_ffi STATIC
  client.cpp
)
target_link_libraries(bitcoin_payjoin_ffi
  PRIVATE
    core_interface
    Payjoin::cpp
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  get_target_property(PAYJOIN_CPP_SOURCES Payjoin::cpp INTERFACE_SOURCES)
  set_source_files_properties(${PAYJOIN_CPP_SOURCES} PROPERTIES
    COMPILE_OPTIONS -Wno-error
  )
endif()

target_link_libraries(bitcoin_wallet PRIVATE bitcoin_payjoin_ffi)
