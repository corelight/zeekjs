# @TEST-EXEC: zeek ./emit-type-events.zeek ./consume-type-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-type-events.js

// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}


zeek.on('zeekjs_test_vector', function(v) {
  zeek.print(`vector: typeof=${typeof(v)} v=${v}`);
});

zeek.on('zeekjs_test_record', function(r) {
  zeek.print(`record: typeof=${typeof(r)} r=${r} r.a=${r?.a} r.b=${r?.b} json=${JSON.stringify(r)}`);
}
);
zeek.on('zeekjs_test_set', function(s) {
  zeek.print(`set: typeof=${typeof(s)} s=${s} s.length=${s?.length} json=${JSON.stringify(s)}`);
});

zeek.on('zeekjs_test_table', function(t1, t2) {
  zeek.print(`table t1: typeof=${typeof(t1)} t=${t1} json=${JSON.stringify(t1)}`);
  zeek.print(`table t2: typeof=${typeof(t2)} t=${t2} json=${JSON.stringify(t2)}`);
});

zeek.on('zeekjs_test_table_addr', function(t) {
  zeek.print(`table addr: typeof=${typeof(t)} t=${t} json=${JSON.stringify(t)}`);
});

zeek.on('zeekjs_test_table_subnet', function(t) {
  zeek.print(`table subnet: typeof=${typeof(t)} t=${t} json=${JSON.stringify(t)}`);
});
@TEST-END-FILE


@TEST-START-FILE emit-type-events.zeek

type MyRecord: record {
  a: count;
  b: string;
};

global zeekjs_test_record: event(r: MyRecord);
global zeekjs_test_vector: event(v: vector of string);
global zeekjs_test_set: event(v: set[string]);
global zeekjs_test_table: event(t1: table[string] of string, t2: table[count] of string);
global zeekjs_test_table_addr: event(t: table[addr] of string);
global zeekjs_test_table_subnet: event(t: table[subnet] of string);

event zeek_init() {
  local v = vector("a", "b");
  event zeekjs_test_vector(v);

  local r = MyRecord($a=42, $b="bvalue");
  event zeekjs_test_record(r);

  local s = set("a", "b", "c");
  event zeekjs_test_set(s);

  local t1: table[string] of string = {
    ["k1"] = "entry 1",
    ["2"] = "entry 2",
  };
  local t2: table[count] of string = {
    [1] = "entry 1",
    [42] = "entry 42",
  };
  event zeekjs_test_table(t1, t2);

  local t3: table[addr] of string = {
    [192.168.0.1] = "router",
    [127.0.0.1] = "localhost",
  };
  event zeekjs_test_table_addr(t3);

  local t4: table[subnet] of string = {
    [192.168.0.0/16] = "home",
    [127.0.0.0/8] = "very home",
  };
  event zeekjs_test_table_subnet(t4);
}

@TEST-END-FILE
