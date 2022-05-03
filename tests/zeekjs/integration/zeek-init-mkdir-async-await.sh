# @TEST-DOC: Javascript doing mkdir() with await during zeek_init().
# @TEST-EXEC: zeek exit_only_after_terminate=T ./await-mkdir.js; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: test -d ./directory
@TEST-START-FILE await-mkdir.js
const fsp = require('fs').promises;

zeek.on('zeek_init', async () => {
  setTimeout(() => {
    console.log('UNEXPECTED TIMEOUT');
    process.exit(1);
  }, 100);
  console.log('Before')
  try {
    await fsp.mkdir('./directory')
    console.log('Created ./directory');
    console.log('Exiting');
    process.exit(0);
  } catch (err) {
    console.log(`UNEXPECTED ERROR: ${err}`);
  }
  console.log('UNEXPECTEDLY REACHED');
});
@TEST-END-FILE
