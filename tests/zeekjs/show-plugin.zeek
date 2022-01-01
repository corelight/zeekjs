# @TEST-EXEC: zeek -NN Corelight::ZeekJS |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
