
# @TEST-DOC: Tests for zeek.invoke
# @TEST-EXEC: zeek ./invoke.zeek ./invoke.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE ./invoke.js
zeek.on('zeek_init', () => {
  try {
    zeek.invoke('Test::non_existing');
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.invoke('Test::test_add', [{"a": "b"}]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.invoke('Test::test_add', [{"a": "b"}, {"a": "b"}]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.invoke('Test::test_add', [1]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.invoke('Test::test_add', [1, 2, 3]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

});
@TEST-END-FILE

@TEST-START-FILE ./invoke.zeek
module Test;

function test_add(a: count, b: count): count {
  return a + b;
}
@TEST-END-FILE
