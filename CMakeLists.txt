cmake_minimum_required(VERSION 3.20)

project(
    feraterra_sdk
    VERSION 4.9.4
    DESCRIPTION "FeraTerra / Arena Exchange Header-Only C++23 64-Byte HFT Wire & Client SDK"
    HOMEPAGE_URL "https://feraterra.app"
    LANGUAGES CXX
)

include(GNUInstallDirs)

# 1. Header-only 64-byte ArenaWireFrame & ArenaITCH binary wire specification
add_library(feraterra_wire INTERFACE)
add_library(feraterra::wire ALIAS feraterra_wire)

target_include_directories(
    feraterra_wire
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(feraterra_wire INTERFACE cxx_std_23)

# 2. Header-only C++23 HFT TCP/UDP/ITCH client & Sovereign WAL ledger verifier
add_library(feraterra_hft_client INTERFACE)
add_library(feraterra::hft_client ALIAS feraterra_hft_client)

target_include_directories(
    feraterra_hft_client
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(feraterra_hft_client INTERFACE cxx_std_23)
target_link_libraries(
    feraterra_hft_client
    INTERFACE
        feraterra_wire
        $<$<PLATFORM_ID:Windows>:ws2_32 bcrypt>
)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    install(
        TARGETS feraterra_wire feraterra_hft_client
        EXPORT feraterraTargets
    )
    install(
        FILES
            "${CMAKE_CURRENT_SOURCE_DIR}/include/arena_wire.hpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/arena_hft_client.hpp"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )
    install(
        EXPORT feraterraTargets
        NAMESPACE feraterra::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/feraterra"
    )
endif()
