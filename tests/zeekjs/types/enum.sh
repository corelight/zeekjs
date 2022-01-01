# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js

zeek.on('zeekjs_test_enum', function(c1, c2) {
  zeek.print(`enum: typeof=${typeof(c1)} c1=${c1} c2=${c2}`)
});

zeek.on('zeekjs_test_enum_table', function(t) {
  zeek.print(`table of enum: typeof=${typeof(t)} json=${JSON.stringify(t)}`);
});
@TEST-END-FILE

@TEST-START-FILE emit-events.zeek
type Color: enum { Red, White, Blue, };

global zeekjs_test_enum: event(c1: Color, c2: Color);
global zeekjs_test_enum_table: event(t: table[Color] of string);

event zeek_init() {
  event zeekjs_test_enum(Blue, White);

  local t: table[Color] of string = {
    [White] = "white",
    [Blue] = "blue",
  };
  event zeekjs_test_enum_table(t);
}
@TEST-END-FILE
