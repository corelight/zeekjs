# @TEST-DOC: Hook implemented in Javascript modifies field records.
# @TEST-EXEC: zeek ./record.zeek ./record.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE record.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}

zeek.hook('Test::policy', function(rec) {
  zeek.print(`JS: Test::policy. Fiddeling with ${JSON.stringify(rec)}`);
  rec.string_field += " from JS!";
  rec.count_field = 4242;

  // This has no effect, because we do not modify
  // the underlying Zeek vector. We could, but it
  // would be work.
  rec.vector_field.push("d") // does not work, and does not crash!

  // This works, but it creates a copy of the array.
  let v = rec.vector_field;
  v.push("e");
  rec.vector_field = v;
})
@TEST-END-FILE

@TEST-START-FILE record.zeek
export {
  type MyRecord: record {
    string_field: string;
    count_field: count;
    vector_field: vector of string;
  };

  global Test::policy: hook(rec: MyRecord);
}

event zeek_init() {
  local my_record = MyRecord(
    $string_field="string1",
    $count_field=42,
    $vector_field=vector("a", "b", "c")
  );

  print "ZEEK: before", my_record;

  hook Test::policy(my_record);

  print "ZEEK: after", my_record;
}
@TEST-END-FILE
