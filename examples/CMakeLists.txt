# Examples for speer

set(SPEER_EXAMPLES
    echo_server
    chat
    libp2p_ping
    libp2p_tcp_full_session
    libp2p_quic_ping
    advanced_stack_demo
)

if(SPEER_ENABLE_DHT)
    list(APPEND SPEER_EXAMPLES dht_example libp2p_kad_bootstrap)
endif()

if(SPEER_ENABLE_RELAY)
    list(APPEND SPEER_EXAMPLES relay_example)
endif()

# speer_chat needs mDNS, so only build it when the discovery layer is on.
if(SPEER_ENABLE_MDNS)
    list(APPEND SPEER_EXAMPLES speer_chat)
endif()

find_package(Threads QUIET)

foreach(example ${SPEER_EXAMPLES})
    set(example_src ${CMAKE_CURRENT_SOURCE_DIR}/${example}.c)
    if(EXISTS ${example_src})
        add_executable(${example} ${example_src})
        target_link_libraries(${example} PRIVATE speer)
        if(Threads_FOUND)
            # speer_chat / chat use pthread on POSIX. Linking unconditionally
            # is harmless on Windows (resolves to nothing).
            target_link_libraries(${example} PRIVATE Threads::Threads)
        endif()
        target_include_directories(${example} PRIVATE
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
    endif()
endforeach()
