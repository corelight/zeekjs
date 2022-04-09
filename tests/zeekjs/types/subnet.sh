# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js
zeek.on('zeekjs_test_subnet', function(test_name, s) {
  zeek.print(`subnet ${test_name} typeof=${typeof(s)} s=${s} json=${JSON.stringify({"s": s})}`);
});

zeek.on('zeek_done', function() {
  zeek.invoke('Test::test_subnet', ["v4-0", "192.168.1.0/24"]);
  zeek.invoke('Test::test_subnet', ["v6-0", "2607:f8b0::/40"]);
  zeek.invoke('Test::test_subnet', ["v6-1", "[2607:f8b0::]/48"]);
});
@TEST-END-FILE

@TEST-START-FILE emit-events.zeek
global zeekjs_test_subnet: event(test_name: string, s: subnet);

event zeek_init() {
  local v4 = 192.168.0.0/24;
  local v6 = [2607:f8b0::]/32;
  event zeekjs_test_subnet("v4", v4);
  event zeekjs_test_subnet("v6", v6);
}

module Test;
function test_subnet(name: string, s: subnet) {
  print(fmt("ZEEK: %s: %s", name, s));
}
@TEST-END-FILE
