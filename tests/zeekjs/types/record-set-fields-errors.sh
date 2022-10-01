# @TEST-DOC: Hook implemented in Javascript modifies field records.
# @TEST-EXEC: zeek ./record.zeek ./record.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE record.js

zeek.hook('Test::policy', function(rec) {
  try {
    rec.string_field = 4242;
    console.log('ERROR: string_field');
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }

  try {
    rec.count_field = "a string";
    console.log('ERROR: count_field');
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }

  try {
    rec.no_such_field = 123;
    console.log('ERROR: no_such_field')
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }

  try {
    rec.addr_field = "192.168.0.300";  // Invalid format
    exit(1);
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }
})
@TEST-END-FILE

@TEST-START-FILE record.zeek
export {
  type MyRecord: record {
    string_field: string;
    count_field: count;
    addr_field: addr;
    vector_field: vector of string;
  };
  global Test::policy: hook(rec: MyRecord);
}

event zeek_init() {
  local my_record = MyRecord(
    $string_field="string1",
    $count_field=42,
    $addr_field=192.168.0.1,
    $vector_field=vector("a", "b", "c")
  );

  hook Test::policy(my_record);
}

@TEST-END-FILE
