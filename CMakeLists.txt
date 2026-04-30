cmake_minimum_required(VERSION 3.15)

project(speer
    VERSION 0.1.0
    DESCRIPTION "speer (small peer) implementation in C"
    HOMEPAGE_URL "https://github.com/speer/speer"
    LANGUAGES C
)

# C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Options
option(SPEER_BUILD_TESTS "Build unit tests" ON)
option(SPEER_BUILD_EXAMPLES "Build examples" ON)
option(SPEER_BUILD_TOOLS "Build tools" ON)
option(SPEER_BUILD_FUZZ "Build fuzzing targets" OFF)
option(SPEER_BUILD_DOCS "Build documentation" OFF)
option(SPEER_ENABLE_WEBPKI "Enable Web PKI support (X.509, RSA, ECDSA)" OFF)
option(SPEER_ENABLE_RELAY "Enable Circuit Relay v2 support" ON)
option(SPEER_ENABLE_DHT "Enable DHT discovery support" ON)
option(SPEER_ENABLE_MDNS "Enable mDNS discovery support" ON)
option(SPEER_ENABLE_COVERAGE "Enable code coverage" OFF)
option(SPEER_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(SPEER_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(SPEER_ENABLE_LTO "Enable Link Time Optimization" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

# Collect source files
set(SPEER_SRCDIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(SPEER_INCDIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SPEER_SUBDIRS
    util
    crypto
    wire
    infra
    libp2p
    transport
    quic
)

# Optional subdirectories based on features
if(SPEER_ENABLE_WEBPKI)
    list(APPEND SPEER_SUBDIRS tls)
endif()

if(SPEER_ENABLE_RELAY)
    list(APPEND SPEER_SUBDIRS relay)
endif()

if(SPEER_ENABLE_DHT OR SPEER_ENABLE_MDNS)
    list(APPEND SPEER_SUBDIRS discovery)
endif()

# Collect all source files
set(SPEER_SOURCES)
foreach(subdir ${SPEER_SUBDIRS})
    file(GLOB subdir_sources ${SPEER_SRCDIR}/${subdir}/*.c)
    list(APPEND SPEER_SOURCES ${subdir_sources})
endforeach()

# Main library source
set(SPEER_CORE_SOURCES
    ${SPEER_SRCDIR}/crypto/crypto.c
)

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600)
    set(SPEER_PLATFORM_LIBS ws2_32 iphlpapi advapi32)
else()
    set(SPEER_PLATFORM_LIBS m)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Linux-specific if needed
    endif()
endif()

# Create library
add_library(speer ${SPEER_SOURCES})

# Include directories
target_include_directories(speer
    PUBLIC
        $<BUILD_INTERFACE:${SPEER_INCDIR}>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${SPEER_SRCDIR}
)

# Add include paths for subdirectories
foreach(subdir ${SPEER_SUBDIRS})
    target_include_directories(speer PRIVATE ${SPEER_SRCDIR}/${subdir})
endforeach()

# Compile options - platform specific
if(MSVC)
    set(SPEER_COMPILE_OPTIONS
        /W4
        /WX
        /wd4996
    )
else()
    set(SPEER_COMPILE_OPTIONS
        -Wall
        -Wextra
        -Werror
        -fno-exceptions
        -fno-unwind-tables
        -ffunction-sections
        -fdata-sections
        -fvisibility=hidden
    )

    # Architecture-specific options
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|i[3456]86")
        list(APPEND SPEER_COMPILE_OPTIONS -msse2 -maes)
    endif()
endif()

# Feature defines
if(SPEER_ENABLE_WEBPKI)
    target_compile_definitions(speer PUBLIC SPEER_WEBPKI=1)
endif()
if(SPEER_ENABLE_RELAY)
    target_compile_definitions(speer PUBLIC SPEER_RELAY=1)
endif()
if(SPEER_ENABLE_DHT)
    target_compile_definitions(speer PUBLIC SPEER_DHT=1)
endif()
if(SPEER_ENABLE_MDNS)
    target_compile_definitions(speer PUBLIC SPEER_MDNS=1)
endif()

# Link options for size reduction
if(MSVC)
    target_link_options(speer PRIVATE /OPT:REF /OPT:ICF)
elseif(NOT WIN32)
    target_link_options(speer PRIVATE -Wl,--gc-sections)
endif()

# LTO
if(SPEER_ENABLE_LTO)
    set_target_properties(speer PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION TRUE
    )
endif()

# Sanitizers
if(SPEER_ENABLE_ASAN)
    target_compile_options(speer PUBLIC -fsanitize=address)
    target_link_options(speer PUBLIC -fsanitize=address)
endif()
if(SPEER_ENABLE_UBSAN)
    target_compile_options(speer PUBLIC -fsanitize=undefined)
    target_link_options(speer PUBLIC -fsanitize=undefined)
endif()

# Coverage
if(SPEER_ENABLE_COVERAGE)
    target_compile_options(speer PUBLIC --coverage)
    target_link_options(speer PUBLIC --coverage)
endif()

# Apply compile options
target_compile_options(speer PRIVATE ${SPEER_COMPILE_OPTIONS})
if(WIN32)
    target_compile_definitions(speer PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
    )
endif()

# Link libraries
target_link_libraries(speer PRIVATE ${SPEER_PLATFORM_LIBS})

# Set library output name
set_target_properties(speer PROPERTIES
    OUTPUT_NAME speer
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    EXPORT_NAME speer
)

# Installation
include(GNUInstallDirs)

install(TARGETS speer
    EXPORT speer-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES ${SPEER_INCDIR}/speer.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Export targets
install(EXPORT speer-targets
    FILE speer-targets.cmake
    NAMESPACE speer::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/speer
)

# Create config file
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/speer-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/speer-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/speer
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/speer-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/speer-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/speer-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/speer
)

# pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/speer.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/speer.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/speer.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Testing
if(SPEER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(SPEER_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Tools
if(SPEER_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# Documentation
if(SPEER_BUILD_DOCS)
    find_package(Doxygen)
    if(Doxygen_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        
        add_custom_target(docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
        )
    else()
        message(WARNING "Doxygen not found, cannot build documentation")
    endif()
endif()

# Print configuration
message(STATUS "")
message(STATUS "speer configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "  Build tests: ${SPEER_BUILD_TESTS}")
message(STATUS "  Build examples: ${SPEER_BUILD_EXAMPLES}")
message(STATUS "  Build tools: ${SPEER_BUILD_TOOLS}")
message(STATUS "  Web PKI: ${SPEER_ENABLE_WEBPKI}")
message(STATUS "  Relay support: ${SPEER_ENABLE_RELAY}")
message(STATUS "  DHT support: ${SPEER_ENABLE_DHT}")
message(STATUS "  mDNS support: ${SPEER_ENABLE_MDNS}")
message(STATUS "  Code coverage: ${SPEER_ENABLE_COVERAGE}")
message(STATUS "  ASan: ${SPEER_ENABLE_ASAN}")
message(STATUS "  UBSan: ${SPEER_ENABLE_UBSAN}")
message(STATUS "  LTO: ${SPEER_ENABLE_LTO}")
message(STATUS "")
