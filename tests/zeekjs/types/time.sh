# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js

zeek.on('zeekjs_test_time_interval', function(ts, i) {
  zeek.print(`time: typeof=${typeof(ts)} ts=${ts} json=${JSON.stringify(ts)}`);
  zeek.print(`interval: typeof=${typeof(i)} i=${i} json=${JSON.stringify(i)}`);
});
@TEST-END-FILE


@TEST-START-FILE emit-events.zeek
global zeekjs_test_time_interval: event(ts: time, i: interval);

event zeek_init() {
  local ts: time = double_to_time(1630163883.86);
  local i: interval= double_to_interval(1.234);
  event zeekjs_test_time_interval(ts, i);
}
@TEST-END-FILE
