# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js

zeek.on('zeek_init', function() {
  zeek.print(`say_hello(true): ${zeek.invoke('Test::say_hello', [true])}`);
  zeek.print(`say_hello(false): ${zeek.invoke('Test::say_hello', [false])}`);
});

zeek.on('zeekjs_test_bool', function(test_name, b) {
  zeek.print(`bool ${test_name} typeof=${typeof(b)} b=${b} json=${JSON.stringify({"b": b})}`);
});
@TEST-END-FILE


@TEST-START-FILE emit-events.zeek
global zeekjs_test_bool: event(test_name: string, b: bool);

event zeek_init() {
  event zeekjs_test_bool("true", T);
  event zeekjs_test_bool("false", F);
}

module Test;
export {
  global say_hello: function(loud: bool): string;
}

function say_hello(loud: bool): string {
  if (loud)
    return "HELLO";

  return "Hello";
}
@TEST-END-FILE
