# @TEST-DOC: Main script source missing zeekjs_init()
# @TEST-EXEC-FAIL: zeek JavaScript::main_script_source="/* nothing */" a.js a.zeek
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr

@TEST-START-FILE a.js
zeek.on('zeek_init', _ => console.log('JS: Never seen'));
@TEST-END-FILE

@TEST-START-FILE a.zeek
event zeek_init() {
  print("Never seen");
}
@TEST-END-FILE
