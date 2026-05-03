# Benchmarks for speer

set(BENCH_TARGETS
    bench_crypto
    bench_wire
    bench_protocol
    bench_throughput
)

foreach(target ${BENCH_TARGETS})
    add_executable(${target} ${target}.c)
    target_link_libraries(${target} PRIVATE speer)
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/util
        ${CMAKE_SOURCE_DIR}/src/crypto
        ${CMAKE_SOURCE_DIR}/src/wire
        ${CMAKE_SOURCE_DIR}/src/infra
        ${CMAKE_SOURCE_DIR}/src/libp2p
        ${CMAKE_SOURCE_DIR}/src/discovery
        ${CMAKE_SOURCE_DIR}/src/relay
        ${CMAKE_SOURCE_DIR}/src/tls
        ${CMAKE_SOURCE_DIR}/src/quic
    )
    if(MSVC)
        target_compile_options(${target} PRIVATE
            $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:/O2>)
    else()
        target_compile_options(${target} PRIVATE -O3)
    endif()
endforeach()

add_custom_target(benchmark
    COMMAND echo "=== Running all benchmarks ==="
    COMMAND echo ""
    COMMAND bench_crypto
    COMMAND bench_wire
    COMMAND bench_protocol
    COMMAND bench_throughput
    DEPENDS ${BENCH_TARGETS}
    COMMENT "Running performance benchmarks"
)

add_custom_target(benchmark-crypto
    COMMAND bench_crypto
    DEPENDS bench_crypto
)

add_custom_target(benchmark-wire
    COMMAND bench_wire
    DEPENDS bench_wire
)

add_custom_target(benchmark-protocol
    COMMAND bench_protocol
    DEPENDS bench_protocol
)
