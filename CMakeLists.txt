cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
cmake_policy(SET CMP0074 NEW)

project(ZeekPluginZeekJS)

include(ZeekPlugin)

find_package(Nodejs REQUIRED)

include_directories(BEFORE ${NODEJS_INCLUDE_DIR} ${UV_INCLUDE_DIR})

zeek_plugin_begin(Corelight ZeekJS)

if ( ZEEK_PLUGIN_INTERNAL_BUILD )
  # This is a hack for the current bug in zeek with doing built in plugins
  set(zeekdeps ${zeekdeps} ${NODEJS_LIBRARY} PARENT_SCOPE)
else()
  zeek_plugin_link_library("${NODEJS_LIBRARY}")
endif()

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
