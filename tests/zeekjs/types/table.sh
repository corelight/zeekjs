# @TEST-DOC: Test modifications of tables from JS
# @TEST-EXEC: zeek ./table.zeek ./table.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE table.js
zeek.hook('zeek_init', function() {
  zeek.print('JS: zeek_init');

  zeek.global_vars['s2c_t']['mystring'] = 42;

  // Can take reference to a Zeek table so we don't need to go through
  // zeek.global_vars all the time.
  let s2r_t = zeek.global_vars['s2r_t'];
  s2r_t['rec1'] = {string_field: 'rec1'};
  s2r_t['rec2'] = {string_field: 'rec2', string_field_optional: 'optional rec2'};

  zeek.global_vars['a2s_t']['192.168.0.1'] = 'This is 192.168.0.1';

   // count to count
  let c2c_t = zeek.global_vars['c2c_t'];
  c2c_t[1] = 2
  c2c_t[2n] = 2n
  // This works because the index setter is called with an actual 3 as unsigned int.
  c2c_t['3'] = 3
  // This works because the ToZeekVal() conversion to count looks for IsNumber(), but looses precision.
  c2c_t[4] = 4.2

  // Yikes, fingers crossed.
  let sn2a_t = zeek.global_vars['sn2a_t'];
  sn2a_t['192.168.0.0/24'] = '192.168.0.1';
  sn2a_t['[::ffff:192.168.1.0]/24'] = '192.168.1.1';
  sn2a_t['[2001:db8::]/64'] = '2001:db8::1';

  let s2vr_t = zeek.global_vars['s2vr_t'];
  s2vr_t['records1'] = [
    {string_field: 'rec1-1'},
    {string_field: 'rec1-2', string_field_optional: 'rec1-2 optional'}
  ];
  s2vr_t['records2'] = [{string_field: 'rec2-1'}];

  // Convert an object to a Zeek table
  let string_tbl_obj = {
    field1: 'string field1',
    field2: 'string field2'
  };
  zeek.invoke('test_string_table', [string_tbl_obj]);

  let addr_tbl_obj = {
    '192.168.0.1': '192.168.0.1',
    '10.0.0.23': '10.0.0.23',
  };
  zeek.invoke('test_string_table', [addr_tbl_obj]);
});
@TEST-END-FILE

@TEST-START-FILE table.zeek
export {
  type MyRecord: record {
    string_field: string;
    string_field_optional: string &optional;
  };

  global test_string_table: function(t: table[string] of string);
  global test_addr_table: function(t: table[addr] of addr);

  global s2c_t: table[string] of count;
  global s2r_t: table[string] of MyRecord;
  global a2s_t: table[addr] of string;
  global c2c_t: table[count] of count;
  global sn2a_t: table[subnet] of addr;
  global s2vr_t: table[string] of vector of MyRecord;
}

function test_string_table(t: table[string] of string) {
  print fmt("test_string_table %s %s", |t|, t);
}

function test_addr_table(t: table[addr] of addr) {
  print fmt("test_addr_table %s %s", |t|, t);
}

event zeek_done() {
  print "s2c_t", cat(s2c_t);
  print "s2r_t", cat(s2r_t);
  print "a2s_t", cat(a2s_t);
  print "c2c_t", cat(c2c_t);
  print "sn2a_t", cat(sn2a_t);
  print "s2vr_t", cat(s2vr_t);
}
@TEST-END-FILE
