# @TEST-DOC: Tests for zeek.invoke with default/optional parameters
# @TEST-EXEC: zeek ./invoke.zeek ./invoke.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE ./invoke.js

zeek.on('zeek_init', () => {
  console.log(`Invoking Test::test_optional: ${zeek.invoke('Test::test_optional', ['cookie'])}`);
  console.log(`Invoking Test::test_optional: ${zeek.invoke('Test::test_optional', ['cookie', 'eikooc'])}`);
});
@TEST-END-FILE

@TEST-START-FILE ./invoke.zeek
module Test;

function test_optional(s: string, t: string &default="abc"): string {
  print(fmt("ZEEK: test_optional: s='%s' t='%s'", s, t));
  return fmt("s=%s t=%s", s, t);
}

@TEST-END-FILE
