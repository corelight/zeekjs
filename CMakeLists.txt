cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
cmake_policy(SET CMP0074 NEW)

project(ZeekPluginZeekJavaScript)

# Establish version numbers in config.h
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

include(ZeekPlugin)

list(PREPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Nodejs REQUIRED)

include_directories(BEFORE ${NODEJS_INCLUDE_DIR} ${UV_INCLUDE_DIR} ${V8_CONFIG_INCLUDE_DIR})

zeek_plugin_begin(Zeek JavaScript)

zeek_plugin_link_library("${NODEJS_LIBRARIES}")

#
# Observed the following errors on Debian with GCC 8.3.0:
#
#   ./build///lib/Corelight-ZeekJS.linux-x86_64.so: undefined symbol: _ZNSt10filesystem7__cxx114path14_M_split_cmptsEv
#
# Adding -lstdc++fs seems to cure this:
#
# https://github.com/k-nuth/infrastructure/pull/14/files
#
if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") AND (${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS 9))
    zeek_plugin_link_library(stdc++fs)
endif()

zeek_plugin_cc(src/IOLoop.cc src/Nodejs.cc src/Plugin.cc src/Types.cc)
zeek_plugin_bif(src/zeekjs.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
