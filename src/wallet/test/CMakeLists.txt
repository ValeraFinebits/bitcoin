# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.
target_sources(test_bitcoin
  PRIVATE
    init_test_fixture.cpp
    wallet_test_fixture.cpp
    db_tests.cpp
    coinselector_tests.cpp
    coinselection_tests.cpp
    feebumper_tests.cpp
    group_outputs_tests.cpp
    init_tests.cpp
    ismine_tests.cpp
    psbt_wallet_tests.cpp
    scriptpubkeyman_tests.cpp
    spend_tests.cpp
    wallet_crypto_tests.cpp
    wallet_interfaces_tests.cpp
    wallet_rpc_tests.cpp
    wallet_tests.cpp
    wallet_transaction_tests.cpp
    walletdb_tests.cpp
    walletload_tests.cpp
)

if(ENABLE_PAYJOIN)
  target_sources(test_bitcoin
    PRIVATE
      payjoin_tests.cpp
      payjoin_manager_tests.cpp
      payjoin_sender_fixture.cpp
      payjoin_sender_tests.cpp
  )
  if(UNIX)
    target_sources(test_bitcoin PRIVATE payjoin_transport_tests.cpp)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      target_link_options(test_bitcoin PRIVATE -Wl,--wrap=curl_multi_poll -Wl,--wrap=curl_multi_perform)
    endif()
  endif()

  if(BUILD_PAYJOIN_INTEGRATION_TESTS)
    add_executable(test_payjoin_integration
      ../../test/main.cpp
      init_test_fixture.cpp
      wallet_test_fixture.cpp
      payjoin_sender_fixture.cpp
      payjoin_integration_tests.cpp
    )
    get_target_property(payjoin_cpp_includes Payjoin::cpp INTERFACE_INCLUDE_DIRECTORIES)
    target_include_directories(test_payjoin_integration SYSTEM PRIVATE ${payjoin_cpp_includes})
    target_link_libraries(test_payjoin_integration
      core_interface
      test_util
      bitcoin_cli
      bitcoin_node
      bitcoin_consensus
      bitcoin_wallet
      bitcoin_payjoin_ffi
      minisketch
      secp256k1
      Boost::headers
      $<TARGET_NAME_IF_EXISTS:USDT::headers>
    )
    # Upstream's global Tokio runtime has no shutdown API. Isolate each case.
    file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/DiscoverPayjoin-$<CONFIG>.cmake"
      CONTENT "set(PAYJOIN_TEST_EXECUTABLE [==[$<TARGET_FILE:test_payjoin_integration>]==])

include([==[${PROJECT_SOURCE_DIR}/cmake/script/DiscoverPayjoinTests.cmake]==])
"
    )
    # TEST_INCLUDE_FILES does not evaluate generator expressions.
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/DiscoverPayjoin.cmake"
      "set(payjoin_test_config [==[${CMAKE_BUILD_TYPE}]==])

if(CTEST_CONFIGURATION_TYPE)
  set(payjoin_test_config \"\${CTEST_CONFIGURATION_TYPE}\")
endif()

include(\"${CMAKE_CURRENT_BINARY_DIR}/DiscoverPayjoin-\${payjoin_test_config}.cmake\")
"
    )
    set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES
      "${CMAKE_CURRENT_BINARY_DIR}/DiscoverPayjoin.cmake"
    )
  endif()
endif()

target_link_libraries(test_bitcoin bitcoin_wallet)
