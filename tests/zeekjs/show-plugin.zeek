# @TEST-EXEC: zeek -NN Zeek::JavaScript |sed -e 's/version.*)/version)/g' >>output
# @TEST-EXEC: echo "===" >> output
# @TEST-EXEC: zeek -NN Zeek::JavaScript ./hello.js |sed -e 's/version.*)/version)/g' >>output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE hello.js
/* hello */
# @TEST-END-FILE
