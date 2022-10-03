# @TEST-DOC: Test modifications of tables from JS
# @TEST-EXEC: zeek ./set.zeek ./set.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE set.js
zeek.hook('zeek_init', function() {
  try {
    zeek.as('subnet_set', 1);
  } catch (error) {
    console.log(`Caught ${error}`);
  }

  try {
    zeek.as('subnet_set', {});
  } catch (error) {
    console.log(`Caught ${error}`);
  }

  try {
    zeek.as('subnet_set', [1]);
  } catch (error) {
    console.log(`Caught ${error}`);
  }

  try {
    zeek.as('subnet_set', ['10.0.0.1/100']);
  } catch (error) {
    console.log(`Caught ${error}`);
  }

  try {
    zeek.as('subnet_set', ['10.0.0.0/8', '192.168.0.0/100']);
  } catch (error) {
    console.log(`Caught ${error}`);
  }

  try {
    // Not even sure how to do this.
    zeek.as('subnet_addr_set', ['10.0.0.0/8', '10.0.0.1']);
  } catch (error) {
    console.log(`Caught ${error}`);
  }
});
@TEST-END-FILE

@TEST-START-FILE set.zeek
export {
  type subnet_set: set[subnet];
  type subnet_addr_set: set[subnet, addr];
}
@TEST-END-FILE
