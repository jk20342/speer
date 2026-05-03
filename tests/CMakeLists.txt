enable_testing()

set(CRYPTO_TEST_SOURCES
    test_crypto.c
    test_sha.c
    test_chacha20_poly1305.c
    test_aes_gcm.c
    test_aes.c
    test_ed25519.c
    test_x25519.c
    test_hkdf.c
    test_hmac.c
    test_poly1305.c
)

add_executable(crypto_tests ${CRYPTO_TEST_SOURCES})

set(SPEER_TEST_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/crypto
    ${CMAKE_SOURCE_DIR}/src/discovery
    ${CMAKE_SOURCE_DIR}/src/infra
    ${CMAKE_SOURCE_DIR}/src/libp2p
    ${CMAKE_SOURCE_DIR}/src/quic
    ${CMAKE_SOURCE_DIR}/src/relay
    ${CMAKE_SOURCE_DIR}/src/tls
    ${CMAKE_SOURCE_DIR}/src/transport
    ${CMAKE_SOURCE_DIR}/src/util
    ${CMAKE_SOURCE_DIR}/src/wire
)

if(WIN32)
    set(SPEER_TEST_PLATFORM_LIBS ws2_32 iphlpapi advapi32)
else()
    set(SPEER_TEST_PLATFORM_LIBS m)
endif()

function(add_speer_test target)
    add_executable(${target} ${ARGN})
    target_include_directories(${target} PRIVATE ${SPEER_TEST_INCLUDE_DIRS})
    target_link_libraries(${target} PRIVATE speer ${SPEER_TEST_PLATFORM_LIBS})
    add_test(NAME ${target} COMMAND ${target})
    set_tests_properties(${target} PROPERTIES TIMEOUT 60)
endfunction()

target_include_directories(crypto_tests PRIVATE ${SPEER_TEST_INCLUDE_DIRS})
target_link_libraries(crypto_tests PRIVATE speer ${SPEER_TEST_PLATFORM_LIBS})
add_test(NAME crypto_tests COMMAND crypto_tests)
set_tests_properties(crypto_tests PROPERTIES TIMEOUT 60)

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
    quic_pkt_robustness_check
    dht_check
    dht_check_negative
    dht_iterative_check
    dht_maintenance_check
    dht_libp2p_check
    dht_libp2p_stream_check
    libp2p_facade_check
    mdns_check
    integration_echo
    dcutr_check
    dcutr_relay_integration_check
    relay_client_check
    relay_libp2p_hop_framing_check
    cpu_features_check
    poly1305_kat_check
    rng_failure_check
    parser_robustness_check
    chacha_counter_check
    ecdsa_p256_check
    identify_check
    libp2p_tcp_primitives_check
)

if(SPEER_ENABLE_WEBPKI)
    list(APPEND SPEER_UNIT_TESTS
        tls13_full_handshake_check
        tls13_negotiation_check
        tls13_negative_vectors_check
        tls13_hrr_check
        tls13_key_update_check
        tls13_psk_ticket_check
        tls13_record_handshake_check
        tls13_openssl_smoke_check
        tls13_auth_check
        webpki_check
    )
endif()

foreach(test_name ${SPEER_UNIT_TESTS})
    add_speer_test(${test_name} ${test_name}.c)
endforeach()

if(SPEER_ENABLE_RELAY AND SPEER_NETWORK_RELAY_TEST)
    add_speer_test(relay_public_hop_check relay_public_hop_check.c)
    set_tests_properties(relay_public_hop_check PROPERTIES LABELS "network" TIMEOUT 120
                                                      SKIP_RETURN_CODE 77)
endif()
