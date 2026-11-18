# test/unit/CMakeLists.txt - unit tests, registered with CTest.
#
# Mirrors test/unit/Makefile.am.  Run with `ctest --test-dir build`, or
# `cmake --build build --target test`.  The tests report TAP-shaped output and
# use automake's standard exit codes, which CTest reads directly: 0 pass,
# 1 fail, 77 skip (declared via SKIP_RETURN_CODE below).

set(TCPR_UNIT_TESTS test_txring test_get_ipv6)

foreach(_test ${TCPR_UNIT_TESTS})
    # unit_globals.c: globals libcommon.a references but does not define
    add_executable(${_test} ${_test}.c unit_globals.c)
    target_include_directories(${_test} PRIVATE
        ${TCPR_GENERATED_INCLUDE_DIRS} ${TCPR_SOURCE_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${_test} PRIVATE common
        ${PCAP_LIBRARIES} ${DNET_LIBRARIES} ${TCPR_SYSTEM_LIBS} ${LNAV_LIBRARIES})
    add_test(NAME ${_test} COMMAND ${_test})
    # automake's standard "this test does not apply here" code
    set_tests_properties(${_test} PROPERTIES SKIP_RETURN_CODE 77)
endforeach()

# Offline integration test for tcprewrite's bidirectional CIDR rewriting. It
# builds its own IPv4/IPv6 pcap and checks addresses plus checksums, so it
# needs neither root nor a NIC and can run under CTest.
if(PYTHON3_EXECUTABLE AND TARGET tcprewrite)
    add_test(NAME bidipnat_rewrite
        COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/bidipnat_check.py
                $<TARGET_FILE:tcprewrite>)
endif()
