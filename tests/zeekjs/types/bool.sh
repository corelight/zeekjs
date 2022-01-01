# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js

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
@TEST-END-FILE
