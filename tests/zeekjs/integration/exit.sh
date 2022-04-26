# @TEST-DOC: Javascript calling zeek.invoke('exit', [1])
# @TEST-EXEC: zeek exit_only_after_terminate=T ./exit.js; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE exit.js
zeek.on('zeek_init', () => {
  setTimeout(() => {
    zeek.print('Invoking exit');
    zeek.invoke('exit', [1]);
  }, 250);
});
