# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js
zeek.on('zeek_init', {priority: 10}, () => {
  zeek.print('JS: print_sum([1,2,3])');
  zeek.event('print_sum', [[1,2,3]]) }
);

zeek.on('zeekjs_test_int', function(test_name, i) {
  zeek.print(`JS: int ${test_name} typeof=${typeof(i)} i=${i} json=${JSON.stringify({"i": i})}`);
});
@TEST-END-FILE


@TEST-START-FILE emit-events.zeek
global zeekjs_test_int: event(test_name: string, i: int);

event print_sum(xs: vector of int) {
  local sum: int = 0;
  for (i in xs)
    sum += xs[i];
   print(fmt("ZEEK: print_sum=%d", sum));
}

event zeek_init() {
  local i0: int = -1;
  event zeekjs_test_int("i0", i0);
  local i1: int = 0;
  event zeekjs_test_int("i1", i1);
  local i2: int = 1;
  event zeekjs_test_int("i2", i2);
}
@TEST-END-FILE
