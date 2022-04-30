# @TEST-DOC: JSON.stringify() only &log attributes using zeek.select_fields()
# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js

// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}

zeek.on('zeekjs_test_select_fields', function(rec) {
  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG);
  zeek.print(JSON.stringify(log_rec, null, 2));
})
@TEST-END-FILE


@TEST-START-FILE emit-events.zeek

type TwoFieldsOneLogRecord: record {
  f1_logged: string &log;
  f2_not_logged: string;
};

type TwoFieldsLogRecord: record {
  f1_logged: string;
  f2_logged: string;
} &log;

type MyRecord: record {
  count_logged: count &log;
  string_not_logged: string;
  two_fields_log_record: TwoFieldsLogRecord &log;
  two_fields_one_log_record: TwoFieldsOneLogRecord &log;
};

global zeekjs_test_select_fields: event(r: MyRecord);

event zeek_init() {
  local my_record = MyRecord(
    $count_logged=4711,
    $string_not_logged="not visible",
    $two_fields_log_record=[$f1_logged="f1", $f2_logged="f2"],
    $two_fields_one_log_record=[$f1_logged="f1", $f2_not_logged="f2"]
  );

  event zeekjs_test_select_fields(my_record);
}

@TEST-END-FILE
