#!/bin/bash
ZEEKJS_HOME=$(dirname $(dirname $(realpath ${BASH_SOURCE[0]})))

if ! command -v zeek > /dev/null; then
    echo "! Missing zeek" >&2
fi

if ! command -v zeek-cut > /dev/null; then
    echo "! Missing zeek-cut" >&2
fi

export ASAN_OPTIONS="abort_on_error=1 detect_odr_violation=0"
export LSAN_OPTIONS=suppressions=$ZEEKJS_HOME/tests/Files/nodejs.lsan.supp
export ZEEK_PLUGIN_PATH=$ZEEKJS_HOME/build
