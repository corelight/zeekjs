# @TEST-EXEC: zeek ./emit-type-events.zeek ./consume-type-events.js
# @TEST-EXEC: grep 'ERROR.*ZeekTableEnumerator' .stderr > errors.stderr
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff errors.stderr
@TEST-START-FILE consume-type-events.js
//
// Maybe this is just ont supported... This already behaves funky in JS
//
// > x = {}
// > x[[1,2]] = 42
// > x["1,2"]
// > 42
//
zeek.on('zeekjs_test_table_multi_index', function(tmi) {
  zeek.print(`table_multi_index: typeof=${typeof(tmi)} json=${JSON.stringify(tmi)}`);
});
@TEST-END-FILE


@TEST-START-FILE emit-type-events.zeek

global zeekjs_test_table_multi_index: event(t: table[count, string] of string);

event zeek_init() {
  local tmi: table[count, string] of string = {
    [1, "1st"] = "first",
    [42, "42th"] = "fourty-second",
  };
  event zeekjs_test_table_multi_index(tmi);
}

@TEST-END-FILE
