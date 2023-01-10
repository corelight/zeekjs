# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js

zeek.on('zeekjs_test_time_interval', function(ts, i) {
  zeek.print(`JS: time: typeof=${typeof(ts)} ts=${ts} json=${JSON.stringify(ts)}`);
  zeek.print(`JS: interval: typeof=${typeof(i)} i=${i} json=${JSON.stringify(i)}`);
});

zeek.on('zeek_done', function() {
  const ts = 1651407414437.5658;
  const d1 = new Date('2022-05-01T12:16:54.437Z');
  const d2 = new Date(ts);

  // number to time uses seconds since epoch, not milliseconds
  zeek.event('zeekjs_test_to_time', ['number', ts / 1000.0]);
  zeek.event('zeekjs_test_to_time', ['date1', d1]);
  zeek.event('zeekjs_test_to_time', ['date2', d2]);

  zeek.event('zeekjs_test_to_interval', ['interval1', 5]);
  zeek.event('zeekjs_test_to_interval', ['interval2', 5.25]);
  zeek.event('zeekjs_test_to_interval', ['interval3', 5.2]);
});
@TEST-END-FILE

@TEST-START-FILE emit-events.zeek
global zeekjs_test_time_interval: event(ts: time, i: interval);
global zeekjs_test_to_time: event(msg: string, ts: time);

event zeek_init() {
  local ts: time = double_to_time(1630163883.86);
  local i: interval = double_to_interval(1.234);
  event zeekjs_test_time_interval(ts, i);
}

event zeekjs_test_to_time(msg: string, t: time) {
  print(fmt("ZEEK: %s %s (%s)", msg, t, time_to_double(t)));
}

event zeekjs_test_to_interval(msg: string, i: interval) {
  print(fmt("ZEEK: %s %s (%s)", msg, i, interval_to_double(i)));
}
@TEST-END-FILE
