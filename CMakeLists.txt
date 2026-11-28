cmake_minimum_required(VERSION 3.20)

project(
    feraterra_sdk
    VERSION 4.9.5
    DESCRIPTION "FeraTerra / Arena Exchange Header-Only C++23 64-Byte HFT Wire & Client SDK"
    HOMEPAGE_URL "https://feraterra.app"
    LANGUAGES CXX
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# 1. Header-only 64-byte ArenaWireFrame & ArenaITCH binary wire specification
add_library(feraterra_wire INTERFACE)
set_target_properties(feraterra_wire PROPERTIES EXPORT_NAME wire)
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
set_target_properties(feraterra_hft_client PROPERTIES EXPORT_NAME hft_client)
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

if(NOT DEFINED PROJECT_IS_TOP_LEVEL)
    if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
        set(PROJECT_IS_TOP_LEVEL ON)
    else()
        set(PROJECT_IS_TOP_LEVEL OFF)
    endif()
endif()

option(FERATERRA_INSTALL "Generate install target" ${PROJECT_IS_TOP_LEVEL})

if(FERATERRA_INSTALL)
    set(FERATERRA_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/feraterra")

    set(_feraterra_config_in_path "${CMAKE_CURRENT_BINARY_DIR}/feraterraConfig.cmake.in")
    set(_feraterra_config_in_content "@PACKAGE_INIT@\n\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/feraterraTargets.cmake\")\nset(feraterra_wire_FOUND TRUE)\nset(feraterra_hft_client_FOUND TRUE)\ncheck_required_components(feraterra)\n")
    set(_feraterra_write_config_in TRUE)
    if(EXISTS "${_feraterra_config_in_path}")
        file(READ "${_feraterra_config_in_path}" _feraterra_existing_config_in)
        if(_feraterra_existing_config_in STREQUAL _feraterra_config_in_content)
            set(_feraterra_write_config_in FALSE)
        endif()
    endif()
    if(_feraterra_write_config_in)
        file(WRITE "${_feraterra_config_in_path}" "${_feraterra_config_in_content}")
    endif()

    configure_package_config_file(
        "${_feraterra_config_in_path}"
        "${CMAKE_CURRENT_BINARY_DIR}/feraterraConfig.cmake"
        INSTALL_DESTINATION "${FERATERRA_CMAKE_INSTALL_DIR}"
        NO_SET_AND_CHECK_MACRO
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/feraterraConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
        ARCH_INDEPENDENT
    )

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
        DESTINATION "${FERATERRA_CMAKE_INSTALL_DIR}"
    )
    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/feraterraConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/feraterraConfigVersion.cmake"
        DESTINATION "${FERATERRA_CMAKE_INSTALL_DIR}"
    )
endif()
