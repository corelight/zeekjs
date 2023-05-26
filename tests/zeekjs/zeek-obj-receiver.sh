# @TEST-DOC: When using zeek.event or zeek.invoke as callbacks crashes happened due to the object not being bound.
# @TEST-EXEC: zeek ./test.js ./test.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE test.js

// Calls cb(name)
function trampoline(cb, name) {
  zeek.print(`JS: trampoline for ${name}`);
  cb(name);
}

zeek.on('zeek_init', () => {
  zeek.print("JS: zeek_init start")
  zeek.event('Test::a');
  trampoline(zeek.event, 'Test::a');
  trampoline(zeek.event.bind({}), 'Test::a');

  zeek.invoke('Test::b');
  trampoline(zeek.invoke, 'Test::b');
  trampoline(zeek.invoke.bind({}), 'Test::b');

  zeek.print("JS: zeek_init end")
});

@TEST-END-FILE

@TEST-START-FILE test.zeek
module Test;

export {
  global a: event();
  global b: function();
}

event Test::a() {
  print "ZEEK: Test::a()";
}

function b() {
  print "ZEEK: Test::b()";
}
@TEST-END-FILE
