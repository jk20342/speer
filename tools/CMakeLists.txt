# Tools for speer

set(SPEER_TOOLS
    keygen
    speer-cli
)

foreach(tool ${SPEER_TOOLS})
    set(tool_src ${CMAKE_CURRENT_SOURCE_DIR}/${tool}.c)
    if(EXISTS ${tool_src})
        add_executable(${tool} ${tool_src})
        target_link_libraries(${tool} PRIVATE speer)
        target_include_directories(${tool} PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/util
            ${CMAKE_SOURCE_DIR}/src/crypto
            ${CMAKE_SOURCE_DIR}/src/infra
        )
        set_target_properties(${tool} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        )
    endif()
endforeach()
