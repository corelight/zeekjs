# @TEST-EXEC: zeek -NN Zeek::JavaScript |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
