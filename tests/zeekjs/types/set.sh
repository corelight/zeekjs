# @TEST-DOC: Test modifications of tables from JS
# @TEST-EXEC: zeek ./set.zeek ./set.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE set.js
zeek.hook('zeek_init', function() {
  zeek.invoke('test_subnet_set', [['192.168.0.0/24', '10.0.0.0/8', '172.16.0.0/12']]);
  zeek.invoke('test_string_set', [['a', 'b', 'c']]);

  // Set is supported, too.
  let s = new Set('defghi');
  zeek.invoke('test_string_set', [s]);
});
@TEST-END-FILE

@TEST-START-FILE set.zeek
export {
  global test_string_set: function(s: set[string]);
}

function test_string_set(s: set[string]) {
  print fmt("test_string_set: %s (%s)", |s|, s);
}

function test_subnet_set(s: set[subnet]) {
  print fmt("test_subnet_set: %s (%s)", |s|, s);
}
@TEST-END-FILE
