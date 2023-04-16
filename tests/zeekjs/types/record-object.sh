# @TEST-DOC: Test Object.entries() and Object.keys()
# @TEST-EXEC: zeek ./record.zeek ./record.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE record.js
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}

zeek.hook('Test::policy', function(msg, rec) {
  console.log(msg);
  let keys = Object.keys(rec);
  let values = Object.values(rec);
  let entries = Object.entries(rec);

  console.log("keys", JSON.stringify(keys));
  console.log("values", JSON.stringify(values));
  console.log("entries", JSON.stringify(entries));
});
@TEST-END-FILE

@TEST-START-FILE record.zeek
export {
  type MyRecord: record {
    s: string;
    c: count;
    sv: vector of string;
    os: string &optional;
    ds: string &default="default string";
  };

  global Test::policy: hook(msg: string, rec: MyRecord);
}

event zeek_init() {
  local my_record = MyRecord(
    $s="string1",
    $c=42,
    $sv=vector("a", "b", "c")
  );

  hook Test::policy("no optional", my_record);

  my_record$os = "optional string";
  hook Test::policy("with optional", my_record);
}
@TEST-END-FILE
