# Fuzzing targets for speer

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(FUZZER_FLAGS "-fsanitize=fuzzer,address,undefined")
else()
    set(FUZZER_FLAGS "")
endif()

set(FUZZ_TARGETS
    fuzz_packet
    fuzz_noise
    fuzz_mdns
    fuzz_dht
    fuzz_tls_handshake
    fuzz_x509
    fuzz_yamux
    fuzz_quic
    fuzz_varint
    fuzz_protobuf
    fuzz_crypto
    fuzz_multistream
    fuzz_relay
    fuzz_peer_id
    fuzz_tls_record
    fuzz_buffer_pool
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
        ${CMAKE_SOURCE_DIR}/src/libp2p
        ${CMAKE_SOURCE_DIR}/src/discovery
        ${CMAKE_SOURCE_DIR}/src/relay
        ${CMAKE_SOURCE_DIR}/src/tls
        ${CMAKE_SOURCE_DIR}/src/quic
        ${CMAKE_SOURCE_DIR}/src/transport
    )

    if(FUZZER_FLAGS)
        target_compile_definitions(${target} PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
        target_compile_options(${target} PRIVATE ${FUZZER_FLAGS})
        target_link_options(${target} PRIVATE ${FUZZER_FLAGS})
    endif()
endforeach()

add_custom_target(fuzz-smoke-test
    COMMAND fuzz_packet || true
    COMMAND fuzz_noise || true
    COMMAND fuzz_mdns || true
    COMMAND fuzz_dht || true
    COMMAND fuzz_tls_handshake || true
    COMMAND fuzz_x509 || true
    COMMAND fuzz_yamux || true
    COMMAND fuzz_quic || true
    COMMAND fuzz_varint || true
    COMMAND fuzz_protobuf || true
    COMMAND fuzz_crypto || true
    COMMAND fuzz_multistream || true
    COMMAND fuzz_relay || true
    COMMAND fuzz_peer_id || true
    COMMAND fuzz_tls_record || true
    COMMAND fuzz_buffer_pool || true
    DEPENDS ${FUZZ_TARGETS}
    COMMENT "Running fuzzing smoke tests"
)

add_custom_target(fuzz-corpus-seed
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/tests/fuzz/corpus
    COMMAND fuzz_packet || true
    COMMAND fuzz_noise || true
    COMMAND fuzz_mdns || true
    DEPENDS ${FUZZ_TARGETS}
    COMMENT "Generating seed corpus for fuzzers"
)
