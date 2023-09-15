
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

    zeek.invoke('Test::test_add', ["a", "b"]);
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

  try {
    zeek.invoke('Test::my_event', ["hello"]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.invoke('Test::not_changing', ["hello"]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.invoke('Test::test_add', 0);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.invoke('Test::test_add', {});
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

});
@TEST-END-FILE

@TEST-START-FILE ./invoke.zeek
module Test;

export {
  global test_add: function(a: count, b: count): count;
  global my_event: event(msg: string, ts: time &default=network_time());
  const not_changing = 5;
}

function test_add(a: count, b: count): count {
  return a + b;
}
event Test::my_event(msg: string, ts: time) {
  print ts, msg;
}
@TEST-END-FILE
