# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(NOT EXISTS "${PAYJOIN_TEST_EXECUTABLE}")
  add_test(payjoin_integration.NOT_BUILT "${CMAKE_COMMAND}" -E false)
  set_tests_properties(payjoin_integration.NOT_BUILT PROPERTIES LABELS payjoin_integration)
  return()
endif()

execute_process(COMMAND "${PAYJOIN_TEST_EXECUTABLE}" --list_content --color_output=no
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 30
)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Payjoin test discovery failed: ${status}: ${stderr}")
endif()

string(REPLACE "\n" ";" lines "${stdout}${stderr}")
set(cases "")
foreach(line IN LISTS lines)
  if(line MATCHES "^    ([A-Za-z0-9_]+)\\*?$")
    list(APPEND cases "${CMAKE_MATCH_1}")
  elseif(NOT line STREQUAL "" AND NOT line MATCHES "^payjoin_integration_tests\\*?$")
    message(FATAL_ERROR "Unexpected Payjoin test hierarchy: ${line}")
  endif()
endforeach()

if(NOT cases)
  message(FATAL_ERROR "No compiled Payjoin integration cases found")
endif()

foreach(test_case IN LISTS cases)
  add_test("payjoin_integration.${test_case}" "${PAYJOIN_TEST_EXECUTABLE}"
    "--run_test=payjoin_integration_tests/${test_case}" --catch_system_error=no --log_level=test_suite
  )
  set_tests_properties("payjoin_integration.${test_case}" PROPERTIES TIMEOUT 120 LABELS payjoin_integration)
endforeach()
