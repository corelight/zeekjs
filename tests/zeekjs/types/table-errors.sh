# @TEST-DOC: Test modifications of tables that don't work.
# @TEST-EXEC: zeek ./table.zeek ./table.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE table.js
zeek.hook('zeek_init', function() {
  try {
    zeek.global_vars['s2c_t']['key'] = '1';
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  try {
    zeek.global_vars['s2r_t'][5] = {};
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  let a2s_t = zeek.global_vars['a2s_t'];

  try {
    a2s_t[42] = 'it is a number';
  } catch (error) {
    console.log(`Caught: ${error}`);
  }
  try {
    a2s_t['scrambled eggs'] = 'not an ip';
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  try {
      a2s_t['192.168.0.300'] = 'bogus ip ip';
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  let c2c_t = zeek.global_vars['c2c_t'];

  try {
      c2c_t['not a count'] = 1;
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  try {
      c2c_t[1] = 'not a count';
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  let sn2a_t = zeek.global_vars['sn2a_t'];

  try {
      sn2a_t['192.168.0.0/24'] = 'not an ip';
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  try {
      sn2a_t['not a subnet'] = '192.168.0.1';
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  let s2vr_t = zeek.global_vars['s2vr_t'];

  try {
      s2vr_t['nonvectype1'] = 'nope';
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  try {
      s2vr_t['nonvectype2'] = {string_field: 'nope'};
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  try {
      s2vr_t['badvectype1'] = [1, 2, 3];
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  try {
      s2vr_t['badobj'] = [{nope: 'nope'}];
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  let ss2c_t = zeek.global_vars['ss2c_t'];
  try {
      ss2c_t['nope,nope'] = 1;
  } catch (error) {
    console.log(`Caught: ${error}`);
  }

  try {
    zeek.invoke('test_triple_string_table', [{x: 'x'}]);
  } catch (error) {
    console.log(`Caught: ${error}`);
  }
});
@TEST-END-FILE

@TEST-START-FILE table.zeek
export {
  type MyRecord: record {
    string_field: string;
    string_field_optional: string &optional;
  };

  type triple_string_table: table[string, string] of string;

  global test_triple_string_table: function(t: triple_string_table);

  global s2c_t: table[string] of count;
  global s2r_t: table[string] of MyRecord;
  global a2s_t: table[addr] of string;
  global c2c_t: table[count] of count;
  global sn2a_t: table[subnet] of addr;
  global s2vr_t: table[string] of vector of MyRecord;
  global ss2c_t: table[string, string] of count;
}

function test_triple_string_table(t: triple_string_table) {
  print fmt("test_string_string_table %s %s", |t|, t);
}

event zeek_done() {
  print "s2c_t", cat(s2c_t);
  print "s2r_t", cat(s2r_t);
  print "a2s_t", cat(a2s_t);
  print "c2c_t", cat(c2c_t);
  print "sn2a_t", cat(sn2a_t);
  print "s2vr_t", cat(s2vr_t);
  print "ss2c_t", cat(ss2c_t);
}
@TEST-END-FILE
