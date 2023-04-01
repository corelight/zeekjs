# @TEST-DOC: Test overriding the main script source
# @TEST-EXEC: zeek JavaScript::main_script_source="console.log('JS: Should not be visible.')" ./test.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE test.zeek
event zeek_init() {
  print("ZEEK: zeek_init");
}
event zeek_done() {
  print("ZEEK: zeek_done");
}
@TEST-END-FILE
