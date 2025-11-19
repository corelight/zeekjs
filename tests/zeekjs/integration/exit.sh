# @TEST-DOC: Javascript calling zeek.invoke('exit', [1]). This ignores ASAN because it directly
#            calls exit(1) in Zeek, so there will not be proper cleanup.
# @TEST-EXEC: ASAN_OPTIONS=${ASAN_OPTIONS}:detect_leaks=0 zeek exit_only_after_terminate=T ./exit.js; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout

# @TEST-START-FILE exit.js
zeek.on('zeek_init', () => {
  setTimeout(() => {
    zeek.print('Invoking exit');
    zeek.invoke('exit', [1]);
  }, 250);
});
# @TEST-END-FILE
