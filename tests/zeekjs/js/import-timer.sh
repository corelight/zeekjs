# @TEST-DOC: Test Javascript creating a Promise at import time (resolved after zeek_init() happened)
# @TEST-EXEC: zeek ./a.js ./a.zeek exit_only_after_terminate=T
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE a.js
zeek.print('JS/a.js - top-level')
new Promise((resolve, reject) => {
  setTimeout(() => {
    zeek.print('JS/a.js: Resolving Promise now and terminating');
    zeek.invoke('terminate');
  }, 100);
})
zeek.on('zeek_init', {priority: 1}, () => {
  zeek.print('JS/a.js: zeek_init()');
})
@TEST-END-FILE

@TEST-START-FILE a.zeek
event do_terminate() {
  if (zeek_is_terminating())
    return;

  print("ZEEK: forced terminate");
  terminate();
}

event zeek_init() {
  print("ZEEK: zeek_init()");
  schedule 1sec { do_terminate() };
}
@TEST-END-FILE
