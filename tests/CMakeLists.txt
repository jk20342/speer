# Unit tests for speer

set(SPEER_UNIT_TESTS
    varint_length_prefix_check
    multiaddr_peer_id_check
    protobuf_sha256_check
    buf_cursor_check
    asn1_check
    buffer_pool_check
    yamux_hdr_check
    yamux_session_check
    multistream_check
    quic_frame_check
    tls_msg_check
    packet_check
    aead_check
    ed25519_check
    noise_check
    x25519_check
    quic_initial_check
    dht_check
    mdns_check
    dcutr_check
    dcutr_relay_integration_check
    relay_client_check
    cpu_features_check
    parser_robustness_check
    rng_failure_check
    poly1305_kat_check
    chacha_counter_check
    ecdsa_p256_check
    quic_pkt_robustness_check
    identify_check
    libp2p_facade_check
    libp2p_tcp_primitives_check
    dht_check_negative
)

if(SPEER_ENABLE_WEBPKI)
    list(APPEND SPEER_UNIT_TESTS webpki_check)
    list(APPEND SPEER_UNIT_TESTS tls13_auth_check)
endif()

foreach(test_name ${SPEER_UNIT_TESTS})
    set(test_src ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c)
    if(EXISTS ${test_src})
        add_executable(${test_name} ${test_src})
        target_link_libraries(${test_name} PRIVATE speer)
        target_include_directories(${test_name} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/util
            ${CMAKE_SOURCE_DIR}/src/crypto
            ${CMAKE_SOURCE_DIR}/src/wire
            ${CMAKE_SOURCE_DIR}/src/infra
            ${CMAKE_SOURCE_DIR}/src/libp2p
            ${CMAKE_SOURCE_DIR}/src/transport
            ${CMAKE_SOURCE_DIR}/src/tls
            ${CMAKE_SOURCE_DIR}/src/quic
            ${CMAKE_SOURCE_DIR}/src/relay
            ${CMAKE_SOURCE_DIR}/src/discovery
        )
        add_test(NAME ${test_name} COMMAND ${test_name})
    endif()
endforeach()

# Integration test
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/integration_echo.c)
    add_executable(integration_echo integration_echo.c)
    target_link_libraries(integration_echo PRIVATE speer)
    target_include_directories(integration_echo PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/util
        ${CMAKE_SOURCE_DIR}/src/crypto
        ${CMAKE_SOURCE_DIR}/src/wire
        ${CMAKE_SOURCE_DIR}/src/infra
    )
endif()

# Fuzzing targets
if(SPEER_BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()
