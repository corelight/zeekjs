# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js
// Render BigInt as string
BigInt.prototype.toJSON = function() {
  return this.toString();
}

zeek.on('zeekjs_test_count', function(test_name, c) {
  zeek.print(`count ${test_name} typeof=${typeof(c)} c=${c} json=${JSON.stringify({"c": c})}`);
});
@TEST-END-FILE


@TEST-START-FILE emit-events.zeek
global zeekjs_test_count: event(test_name: string, c: count);

event zeek_init() {
  local c0: count = 900719925474099;
  event zeekjs_test_count("okay", c0);

  local c1: count = 9007199254740991;
  event zeekjs_test_count("max safe integer", c1);

  # Converted into BigInt and represented as string, so we do not
  # loose precision in the output.
  local c2: count = 90071992547409910;
  event zeekjs_test_count("too big", c2);
}
@TEST-END-FILE
