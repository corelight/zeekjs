# @TEST-DOC: Invoke fs.unlinkSync() and trigger an uncaught exception. We keep going because of JavaScript::exit_on_uncaught_exceptions=F.
# @TEST-EXEC: zeek unlink-sync.js unlink-sync.zeek
# @TEST-EXEC: ! grep 'async hook stack has become corrupted' .stderr
# Should be exactly 10...
# @TEST-EXEC: grep Uncaught .stderr > uncaught
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff uncaught
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE unlink-sync.js
fs = require('fs');
var c = 0;
let i = setInterval(unlink, 10);

function unlink() {
  if (++c == 10) {
    console.log(`We tried unlinking ${c} times. Enough.`);
    clearInterval(i);
    zeek.invoke('terminate');
  }

  fs.unlinkSync('does-not-exist');
}
@TEST-END-FILE

@TEST-START-FILE unlink-sync.zeek
redef exit_only_after_terminate=T;
redef JavaScript::exit_on_uncaught_exceptions=F;

event terminate_now() {
  if (zeek_is_terminating())
    return;

  terminate();
}

event zeek_init() {
  schedule 1000msec { terminate_now() };
}
@TEST-END-FILE
