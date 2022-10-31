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


find_path(NODEJS_INCLUDE_DIR
    NAMES node/node.h
    HINTS ${NODEJS_ROOT_DIR}/include
    NO_DEFAULT_PATH
)
find_path(NODEJS_INCLUDE_DIR
    NAMES node/node.h
)

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
    "node"
    "libnode.so"
    "libnode.so.83"
    "libnode.so.93"
    "libnode.so.102"
    "libnode.so.108"
    "libnode.so.111"
)

find_library(NODEJS_LIBRARY
    NAMES ${nodejs_known_names}
    PATHS ${NODEJS_ROOT_DIR}/lib
    NO_DEFAULT_PATH
)
find_library(NODEJS_LIBRARY
    NAMES ${nodejs_known_names}
)

find_package_handle_standard_args(Nodejs DEFAULT_MSG
    NODEJS_INCLUDE_DIR
    UV_INCLUDE_DIR
    V8_CONFIG_INCLUDE_DIR
    NODEJS_LIBRARY
)
message(STATUS "     library: ${NODEJS_LIBRARY}")
message(STATUS "        uv.h: ${UV_INCLUDE_DIR}")
message(STATUS "  v8config.h: ${V8_CONFIG_INCLUDE_DIR}")
