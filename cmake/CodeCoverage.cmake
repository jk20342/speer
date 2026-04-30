# CodeCoverage.cmake
# Provides targets for generating code coverage reports
#
# Usage:
#   cmake -B build -DSPEER_ENABLE_COVERAGE=ON
#   cmake --build build
#   ctest --test-dir build
#   cmake --build build --target coverage

find_program(LCOV_PATH lcov)
find_program(GENHTML_PATH genhtml)

if(SPEER_ENABLE_COVERAGE)
    if(NOT LCOV_PATH)
        message(WARNING "lcov not found! Coverage report will not be available.")
    endif()
    if(NOT GENHTML_PATH)
        message(WARNING "genhtml not found! Coverage report will not be available.")
    endif()

    if(LCOV_PATH AND GENHTML_PATH)
        # Coverage target
        add_custom_target(coverage
            # Capture coverage data
            COMMAND ${LCOV_PATH} --capture --directory ${CMAKE_BINARY_DIR}
                --output-file ${CMAKE_BINARY_DIR}/coverage.info
                --rc lcov_branch_coverage=1
            # Remove system and test files
            COMMAND ${LCOV_PATH} --remove ${CMAKE_BINARY_DIR}/coverage.info
                '/usr/*'
                '/opt/*'
                '*/tests/*'
                '*/test/*'
                '*/CMakeFiles/*'
                '*/examples/*'
                '*/tools/*'
                --output-file ${CMAKE_BINARY_DIR}/coverage_filtered.info
                --rc lcov_branch_coverage=1
            # Generate HTML report
            COMMAND ${GENHTML_PATH} ${CMAKE_BINARY_DIR}/coverage_filtered.info
                --output-directory ${CMAKE_BINARY_DIR}/coverage_report
                --title "speer Code Coverage"
                --show-details
                --legend
                --rc lcov_branch_coverage=1
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Generating code coverage report"
        )

        # Coverage cleanup target
        add_custom_target(coverage-clean
            COMMAND ${LCOV_PATH} --zerocounters --directory ${CMAKE_BINARY_DIR}
            COMMAND ${CMAKE_COMMAND} -E remove
                ${CMAKE_BINARY_DIR}/coverage.info
                ${CMAKE_BINARY_DIR}/coverage_filtered.info
            COMMAND ${CMAKE_COMMAND} -E remove_directory
                ${CMAKE_BINARY_DIR}/coverage_report
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Cleaning up coverage data"
        )

        # Coverage info target (for CI)
        add_custom_target(coverage-info
            COMMAND ${LCOV_PATH} --list ${CMAKE_BINARY_DIR}/coverage_filtered.info
            DEPENDS coverage
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Displaying coverage summary"
        )

        message(STATUS "Code coverage enabled. Run 'make coverage' after tests.")
    endif()
endif()

# Function to add coverage flags to a target
function(target_add_coverage_flags target)
    if(SPEER_ENABLE_COVERAGE)
        target_compile_options(${target} PRIVATE --coverage -fprofile-arcs -ftest-coverage)
        target_link_options(${target} PRIVATE --coverage -fprofile-arcs -ftest-coverage)
    endif()
endfunction()
