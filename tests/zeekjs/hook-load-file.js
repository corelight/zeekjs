# @TEST-DOC: Tests around HookLoadFile
# @TEST-EXEC: zeek a js a.z a.ze a.js a.cjs
# @TEST-EXEC: btest-diff .stdout
@TEST-START-FILE a
event zeek_init() &priority=0 {
  print("PASS: a was loaded as Zeek file.");
}
@TEST-END-FILE

@TEST-START-FILE a.z
event zeek_init() &priority=-1 {
  print("PASS: a.z was loaded as Zeek file.");
}
@TEST-END-FILE

@TEST-START-FILE js
event zeek_init() &priority=-2 {
  print("PASS: js was loaded as Zeek file.");
}
@TEST-END-FILE

@TEST-START-FILE ze
event zeek_init() &priority=-3 {
  print("PASS: @FILENAME was loaded as Zeek file.");
}
@TEST-END-FILE

@TEST-START-FILE js
event zeek_init() &priority=-4 {
  print("PASS: js was loaded as Zeek file.");
}
@TEST-END-FILE

@TEST-START-FILE a.ze
event zeek_init() &priority=-5 {
  print("PASS: a.ze was loaded as Zeek file.");
}
@TEST-END-FILE

@TEST-START-FILE a.js
zeek.on('zeek_init', { priority: -7 }, function() {
  zeek.print('PASS: a.js was loaded as Javascript file.');
});
@TEST-END-FILE

@TEST-START-FILE a.cjs
zeek.on('zeek_init', { priority: -8 }, function() {
  zeek.print('PASS: a.cjs was loaded as Javascript file.');
});
@TEST-END-FILE
