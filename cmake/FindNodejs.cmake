# - Try to find Node.js headers and libraries.
#
# Usage of this module as follows:
#
#     find_package(Nodejs)
#
# Variables used by this module, they can change the default behaviour and
# need to be set before calling find_package:
#
#  NODEJS_ROOT_DIR   Set this variable to the root installation of
#                    Node.js if the module has problems finding
#                    the proper installation path.
#
include(FindPackageHandleStandardArgs)


if ( NODEJS_ROOT_DIR )
    find_path(NODEJS_INCLUDE_DIR
        NAMES node/node.h
        HINTS ${NODEJS_ROOT_DIR}/include
        NO_DEFAULT_PATH
    )
else ()
    find_path(NODEJS_INCLUDE_DIR
        NAMES node/node.h
    )
endif ()

# Find the location of uv.h, prefer to use the one shipped within
# the node installation.
find_path(UV_INCLUDE_DIR
    NAMES uv.h
    PATHS ${NODEJS_INCLUDE_DIR}/node
    NO_DEFAULT_PATH
)
find_path(UV_INCLUDE_DIR
    NAMES uv.h
)

# Find the v8config.h, prefer to use the one shipped within
# the node installation.
find_path(V8_CONFIG_INCLUDE_DIR
    NAMES v8config.h
    PATHS ${NODEJS_INCLUDE_DIR}/node
    NO_DEFAULT_PATH
)

find_path(V8_CONFIG_INCLUDE_DIR
    NAMES v8config.h
)

#
# libnode.so.83, Fedora 34, node 14.18
# libnode.so.93, Fedora 35, node 16.13
# libnode.so.102, node 17.3.0
# libnode.so.111, node 19.0.0
#
set(nodejs_known_names
    "libnode.so" "libnode.dylib"
    "libnode.so.83" "libnode.83.dylib"
    "libnode.so.93" "libnode.93.dylib"
    "libnode.so.102" "libnode.102.dylib"
    "libnode.so.108" "libnode.108.dylib"
    "libnode.so.111" "libnode.111.dylib"
    "libnode.so.115" "libnode.115.dylib"
)

if ( NODEJS_ROOT_DIR )
    find_library(NODEJS_LIBRARY
        NAMES ${nodejs_known_names}
        PATHS ${NODEJS_ROOT_DIR}/lib
        NO_DEFAULT_PATH
    )
else ()
    find_library(NODEJS_LIBRARY
        NAMES ${nodejs_known_names}
    )
endif ()

if ( NODEJS_INCLUDE_DIR )
    # Extract the version from node_version.h
    file(STRINGS "${NODEJS_INCLUDE_DIR}/node/node_version.h" NODEJS_MAJOR_VERSION_H  REGEX "^#define NODE_MAJOR_VERSION [0-9]+$")
    file(STRINGS "${NODEJS_INCLUDE_DIR}/node/node_version.h" NODEJS_MINOR_VERSION_H  REGEX "^#define NODE_MINOR_VERSION [0-9]+$")
    file(STRINGS "${NODEJS_INCLUDE_DIR}/node/node_version.h" NODEJS_PATCH_VERSION_H  REGEX "^#define NODE_PATCH_VERSION [0-9]+$")
    string(REGEX REPLACE "^.*NODE_MAJOR_VERSION ([0-9]+)$" "\\1" NODEJS_MAJOR_VERSION "${NODEJS_MAJOR_VERSION_H}")
    string(REGEX REPLACE "^.*NODE_MINOR_VERSION ([0-9]+)$" "\\1" NODEJS_MINOR_VERSION "${NODEJS_MINOR_VERSION_H}")
    string(REGEX REPLACE "^.*NODE_PATCH_VERSION ([0-9]+)$" "\\1" NODEJS_PATCH_VERSION "${NODEJS_PATCH_VERSION_H}")

    set(NODEJS_VERSION "${NODEJS_MAJOR_VERSION}.${NODEJS_MINOR_VERSION}.${NODEJS_PATCH_VERSION}")

    # If libnode was built with a shared libuv, ensure we add libuv
    # into NODEJS_LIBRARIES. Specifically when building Zeek with ZeekJS
    # builtin, libuv needs to be propagated as a link dependency to
    # the Zeek executable as the plugin is using libuv functionality
    # directly. Depending on the distro the configuration is in node/config.gypi
    # or node/config-<arch>.gypi.
    file(GLOB NODE_CONFIG_GYPIS "${NODEJS_INCLUDE_DIR}/node/config*gypi")
    foreach ( GYPI ${NODE_CONFIG_GYPIS} )
        file(STRINGS "${GYPI}" HAVE_SHARED_LIB_UV REGEX "node_shared_libuv.*:.*'true'")
        if ( HAVE_SHARED_LIB_UV )
            find_package(LibUV REQUIRED)
            break ()
        endif ()
    endforeach ()
endif ()

find_package_handle_standard_args(Nodejs
    REQUIRED_VARS NODEJS_INCLUDE_DIR UV_INCLUDE_DIR V8_CONFIG_INCLUDE_DIR NODEJS_LIBRARY
    VERSION_VAR NODEJS_VERSION
)

if ( Nodejs_FOUND )
  set(NODEJS_LIBRARIES ${NODEJS_LIBRARY} ${LibUV_LIBRARIES})

  message(STATUS "     version: ${NODEJS_VERSION}")
  message(STATUS "   libraries: ${NODEJS_LIBRARIES}")
  message(STATUS "        uv.h: ${UV_INCLUDE_DIR}")
  message(STATUS "  v8config.h: ${V8_CONFIG_INCLUDE_DIR}")
endif ()
