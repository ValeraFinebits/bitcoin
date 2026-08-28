# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "ENABLE_PAYJOIN currently requires a native Linux build")
endif()

find_program(PAYJOIN_CARGO_EXECUTABLE cargo REQUIRED)
find_program(PAYJOIN_RUSTC_EXECUTABLE rustc REQUIRED)

set(PAYJOIN_RUST_ROOT "${PROJECT_SOURCE_DIR}/payjoin")
set(PAYJOIN_RUST_TOOLCHAIN "1.85.1")

execute_process(
  COMMAND ${CMAKE_COMMAND} -E env
    "RUSTUP_TOOLCHAIN=${PAYJOIN_RUST_TOOLCHAIN}"
    "${PAYJOIN_RUSTC_EXECUTABLE}" --version
  OUTPUT_VARIABLE PAYJOIN_RUSTC_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
  COMMAND_ERROR_IS_FATAL ANY
)
if(NOT PAYJOIN_RUSTC_VERSION MATCHES "^rustc ${PAYJOIN_RUST_TOOLCHAIN}([ (]|$)")
  message(FATAL_ERROR
    "Payjoin requires rustc ${PAYJOIN_RUST_TOOLCHAIN}, got: ${PAYJOIN_RUSTC_VERSION}")
endif()

if(NOT EXISTS "${PAYJOIN_RUST_ROOT}/payjoin-ffi/Cargo.toml" OR
   NOT EXISTS "${PAYJOIN_RUST_ROOT}/Cargo-recent.lock")
  message(FATAL_ERROR "The payjoin submodule is missing or incomplete")
endif()

set(PAYJOIN_WORKSPACE_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust-workspace")
set(PAYJOIN_CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust-target")
set(PAYJOIN_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(PAYJOIN_RUST_STATIC "${PAYJOIN_CARGO_TARGET_DIR}/release/libpayjoin_ffi.a")
set(PAYJOIN_RUST_SHARED "${PAYJOIN_CARGO_TARGET_DIR}/release/libpayjoin_ffi.so")
set(PAYJOIN_BINDGEN "${PAYJOIN_CARGO_TARGET_DIR}/release/uniffi-bindgen")

file(GLOB_RECURSE PAYJOIN_RUST_INPUTS CONFIGURE_DEPENDS
  "${PAYJOIN_RUST_ROOT}/*.rs"
  "${PAYJOIN_RUST_ROOT}/*.toml"
)
list(APPEND PAYJOIN_RUST_INPUTS "${PAYJOIN_RUST_ROOT}/Cargo-recent.lock")

add_custom_command(
  OUTPUT "${PAYJOIN_GENERATED_DIR}/payjoin.cpp"
  BYPRODUCTS
    "${PAYJOIN_RUST_STATIC}"
    "${PAYJOIN_RUST_SHARED}"
    "${PAYJOIN_BINDGEN}"
    "${PAYJOIN_GENERATED_DIR}/payjoin.hpp"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${PAYJOIN_GENERATED_DIR}"
  COMMAND ${CMAKE_COMMAND} -E rm -rf "${PAYJOIN_WORKSPACE_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    "${PAYJOIN_RUST_ROOT}"
    "${PAYJOIN_WORKSPACE_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${PAYJOIN_RUST_ROOT}/Cargo-recent.lock"
    "${PAYJOIN_WORKSPACE_DIR}/Cargo.lock"
  COMMAND ${CMAKE_COMMAND} -E chdir "${PAYJOIN_WORKSPACE_DIR}"
    ${CMAKE_COMMAND} -E env "RUSTUP_TOOLCHAIN=${PAYJOIN_RUST_TOOLCHAIN}"
    ${PAYJOIN_CARGO_EXECUTABLE} build
    --package payjoin-ffi
    --lib
    --bin uniffi-bindgen
    --features cpp
    --release
    --target-dir "${PAYJOIN_CARGO_TARGET_DIR}"
    --locked
  COMMAND ${CMAKE_COMMAND} -E chdir "${PAYJOIN_WORKSPACE_DIR}/payjoin-ffi"
    ${CMAKE_COMMAND} -E env
    "CARGO=${PAYJOIN_CARGO_EXECUTABLE}"
    "RUSTUP_TOOLCHAIN=${PAYJOIN_RUST_TOOLCHAIN}"
    "UNIFFI_BINDGEN_LANGUAGE=cpp"
    "${PAYJOIN_BINDGEN}"
    --library "${PAYJOIN_RUST_SHARED}"
    --out-dir "${PAYJOIN_GENERATED_DIR}"
    --skip-async
  DEPENDS ${PAYJOIN_RUST_INPUTS}
  VERBATIM
)

add_custom_target(payjoin_rust_codegen DEPENDS "${PAYJOIN_GENERATED_DIR}/payjoin.cpp")

add_library(bitcoin_payjoin_ffi STATIC
  "${PAYJOIN_GENERATED_DIR}/payjoin.cpp"
)
add_dependencies(bitcoin_payjoin_ffi payjoin_rust_codegen)
target_include_directories(bitcoin_payjoin_ffi SYSTEM PUBLIC "${PAYJOIN_GENERATED_DIR}")
target_link_libraries(bitcoin_payjoin_ffi
  PRIVATE "${PAYJOIN_RUST_STATIC}" Threads::Threads ${CMAKE_DL_LIBS} m rt util
)

target_sources(bitcoin_node PRIVATE client.cpp)
target_link_libraries(bitcoin_node PRIVATE bitcoin_payjoin_ffi)
