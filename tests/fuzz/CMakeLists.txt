# Fuzzing targets for speer

# Find libFuzzer or use standalone mode
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(FUZZER_FLAGS "-fsanitize=fuzzer,address,undefined")
else()
    # GCC or other - use standalone mode
    set(FUZZER_FLAGS "")
endif()

set(FUZZ_TARGETS
    fuzz_packet
    fuzz_noise
    fuzz_mdns
)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.c)
    target_link_libraries(${target} PRIVATE speer)
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/util
        ${CMAKE_SOURCE_DIR}/src/crypto
        ${CMAKE_SOURCE_DIR}/src/wire
        ${CMAKE_SOURCE_DIR}/src/infra
    )

    if(FUZZER_FLAGS)
        target_compile_definitions(${target} PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
        target_compile_options(${target} PRIVATE ${FUZZER_FLAGS})
        target_link_options(${target} PRIVATE ${FUZZER_FLAGS})
    endif()
endforeach()

# Create a target to run all fuzzers briefly
add_custom_target(fuzz-smoke-test
    COMMAND fuzz_packet || true
    COMMAND fuzz_noise || true
    COMMAND fuzz_mdns || true
    DEPENDS ${FUZZ_TARGETS}
    COMMENT "Running fuzzing smoke tests"
)
