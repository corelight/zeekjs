# @TEST-DOC: Things we do not support with tables. Outside of rendering keys as strings I don't know how to go about that.
# @TEST-EXEC: zeek ./emit-type-events.zeek ./consume-type-events.js
# @TEST-EXEC: btest-diff .stdout
@TEST-START-FILE consume-type-events.js
//
// Maybe this is just not supported... This already behaves funky in JS
//
// > x = {}
// > x[[1,2]] = 42
// > x["1,2"]
// > 42
//
zeek.on('zeekjs_test_table_multi_index', function(tmi) {
  try {
    zeek.print(`table_multi_index: typeof=${typeof(tmi)} json=${JSON.stringify(tmi)}`);
  } catch (e) {
    zeek.print(`Caught: ${e}`);
  }
});

zeek.on('zeekjs_test_table_record_index', function(tr) {
  try {
    zeek.print(`table_record_index: typeof=${typeof(tr)} json=${JSON.stringify(tr)}`);
  } catch (e) {
    zeek.print(`Caught: ${e}`);
  }
});

zeek.on('zeekjs_test_table_composite_index', function(tc) {
  try {
    zeek.print(`table_composite_index: typeof=${typeof(tc)} json=${JSON.stringify(tc)}`);
  } catch (e) {
    zeek.print(`Caught: ${e}`);
  }
});
@TEST-END-FILE


@TEST-START-FILE emit-type-events.zeek
type MyRecord: record {
  a: string;
  b: string;
};

global zeekjs_test_table_multi_index: event(t: table[count, string] of string);
global zeekjs_test_table_record_index: event(t: table[MyRecord] of string);
global zeekjs_test_table_composite_index: event(t: table[count, count] of string);

event zeek_init() {
  local tmi: table[count, string] of string = {
    [1, "1st"] = "first",
    [42, "42th"] = "fourty-second",
  };
  event zeekjs_test_table_multi_index(tmi);

  local tr: table[MyRecord] of string = {
    [[$a="1", $b="2"]] = "first",
    [[$a="3", $b="4"]] = "second",
  };
  event zeekjs_test_table_record_index(tr);

  local tc: table[count, count] of string = {
    [1, 2] = "first",
    [3, 4] = "second",
  };
  event zeekjs_test_table_composite_index(tc);
}
@TEST-END-FILE
