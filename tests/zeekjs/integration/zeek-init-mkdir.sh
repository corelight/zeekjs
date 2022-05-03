# @TEST-DOC: Javascript doing mkdir() during zeek_init() didn't work as we never entered the Javascript loop.
# @TEST-EXEC: zeek exit_only_after_terminate=T ./mkdir.js; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: test -d ./directory
@TEST-START-FILE mkdir.js
const fs = require('fs');

zeek.on('zeek_init', () => {
  setTimeout(() => {
    console.log('UNEXPECTED TIMEOUT');
    process.exit(1);
  }, 100);
  console.log('Before')
  fs.mkdir('./directory', (err) => {
    console.log('Created ./directory');
    if (err) {
      console.log(`UNEXPECTED ERROR: ${err}`);
    }
    console.log('Exiting');
    process.exit(0);
  });
  console.log('After');
});
@TEST-END-FILE
