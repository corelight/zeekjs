# @TEST-EXEC: zeek -NN Zeek::JavaScript |sed -e 's/version.*)/version)/g' >>output
# @TEST-EXEC: echo "===" >> output
# Disable leak checking because -N or -NN does not call Plugin::Done() - probably more of a bug on the Zeek side.
# @TEST-EXEC: ASAN_OPTIONS=${ASAN_OPTIONS}:detect_leaks=0 zeek -NN Zeek::JavaScript ./hello.js |sed -e 's/version.*)/version)/g' >>output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE hello.js
/* hello */
# @TEST-END-FILE
