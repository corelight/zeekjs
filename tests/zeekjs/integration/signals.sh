# @TEST-DOC: Javascript taking over Zeek's SIGINT and SIGTERM - don't do this unless your first name starts with an S and your last name is Hall.
# @TEST-EXEC: zeek exit_only_after_terminate=T ./signal.js ./exit_code.zeek; echo "Shell got: $?"
# @TEST-EXEC: zeek exit_only_after_terminate=T ./signal.js ./exit_code.zeek Test::exit_code=1; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE signal.js
zeek.on('zeek_init', () => {
  console.log('Register SIGINT handler');
  process.on('SIGINT', () => {
    console.log('Got SIGINT!');
  });
  console.log('Register SIGTERM handler');
  process.on('SIGTERM', () => {
    const exit_code=parseInt(zeek.global_vars['Test::exit_code']);
    console.log(`Got SIGTERM - exit(${exit_code}) - ${typeof(exit_code)}`);
    process.exit(exit_code);
  });

  setTimeout(() => {
    console.log('Sending SIGINT');
    process.kill(process.pid, 'SIGINT');
  }, 100);
  setTimeout(() => {
    console.log('Sending SIGTERM');
    process.kill(process.pid, 'SIGTERM');
  }, 200);
});

setTimeout(() => {
  console.log('Not seen: Forcing exit')
  process.exit(1);
}, 1000);
@TEST-END-FILE

@TEST-START-FILE exit_code.zeek
module Test;
export {
  const exit_code: count = 0 &redef;
}
