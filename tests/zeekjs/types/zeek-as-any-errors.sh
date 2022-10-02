# @TEST-DOC: Test zeek.as() and calling functions with any
# @TEST-EXEC: zeek ./as-any-errors.zeek ./as-any-errors.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE as-any-errors.js
zeek.hook('zeek_init', function() {
  try {
    zeek.as('count');
  } catch (error) {
    console.log(`Caught: ${error}`)
  }

  try {
    zeek.as(1, 1);
  } catch (error) {
    console.log(`Caught: ${error}`)
  }

  try {
    zeek.as('countx', 1);
  } catch (error) {
    console.log(`Caught: ${error}`)
  }

  try {
    zeek.as('NonExistingRecordType', 1);
  } catch (error) {
    console.log(`Caught: ${error}`)
  }

  try {
    zeek.as('MyRecord', 1);
  } catch (error) {
    console.log(`Caught: ${error}`)
  }

  try {
    zeek.as('MyRecord', {count_field: 1, string_field: 'y', string_field_optional: 1});
  } catch (error) {
    console.log(`Caught: ${error}`)
  }

});
@TEST-END-FILE

@TEST-START-FILE as-any-errors.zeek

export {

  type MyRecord: record {
    count_field: count;
    string_field: string;
    string_field_optional: string &optional;
  };
}
# Unused
@TEST-END-FILE
