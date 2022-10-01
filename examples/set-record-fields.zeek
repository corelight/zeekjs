# The JS code implements the Test::policy hook and modifies the s field.
@load ./set-record-fields.js

module Test;

export {

  type MyRecord: record {
    s: string;
  };

  global Test::policy: hook(r: MyRecord);
}

event zeek_init() {
  local r: MyRecord = [$s="hello"];
  print fmt("ZEEK: %s", r);
  hook Test::policy(r);
  print fmt("ZEEK: %s", r);
}
