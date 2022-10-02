# @TEST-DOC: Test zeek.as() and calling functions with any
# @TEST-EXEC: zeek ./as-any.zeek ./as-any.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE as-any.js
zeek.hook('zeek_init', function() {

  let c = zeek.as('count', 42);
  zeek.print(`JS: typeof(c)=${typeof(c)} c=${c}`);
  zeek.invoke('do_anything', ['test with count', c]);

  let r = zeek.as('MyRecord', {count_field: 42, string_field: 's1'});
  zeek.print(`JS: typeof(r)=${typeof(c)} r=${r}`);
  zeek.invoke('do_anything', ['test with MyRecord', r]);
});
@TEST-END-FILE

@TEST-START-FILE as-any.zeek
export {
  type MyRecord: record {
    count_field: count;
    string_field: string;
    string_field_optional: string &optional;
  };

  global do_anything: function(s: string, a: any);
}

function do_anything(s: string, a: any) {
  print fmt("ZEEK: %s: do_anything(%s: %s)", s, a, type_name(a));
}
@TEST-END-FILE
