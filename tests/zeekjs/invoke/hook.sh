# @TEST-DOC: Invoke a hook and verify the return value represents whether break was used or not.
# @TEST-EXEC: zeek ./hook.zeek ./hook.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE ./hook.js

zeek.on('zeek_init', () => {
  let r1 = zeek.invoke("Test::my_hook", [0]);
  zeek.print(`JS: result ${r1}`);
  let r2 = zeek.invoke("Test::my_hook", [1]);
  zeek.print(`JS: result ${r2}`);
});
@TEST-END-FILE

@TEST-START-FILE ./hook.zeek
module Test;

export {
  global my_hook: hook(a: count);
}

hook Test::my_hook(a: count) {
  local do_break = a == 1;
  print "ZEEK: hook invoked", a, "breaking?", do_break;
  if ( do_break )
    break;
}
@TEST-END-FILE
