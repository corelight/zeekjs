# @TEST-DOC: Attempting a declared but not defined function would blow up with a nullptr ref.
# @TEST-EXEC: zeek ./invoke.zeek ./invoke.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE ./invoke.js

zeek.on('zeek_init', () => {
  try {
    zeek.invoke('Test::no_val', ['hello']);
  } catch (e) {
    console.log(`Caught: ${e}`);
  }
});
@TEST-END-FILE

@TEST-START-FILE ./invoke.zeek
module Test;

export {
  # Not implemented.
  global no_val: function(s: string);
}
@TEST-END-FILE
