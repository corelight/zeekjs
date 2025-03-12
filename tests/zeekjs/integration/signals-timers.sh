# @TEST-DOC: Regression test for #11 triggering an endless loop when sending a signal when the Node.js loop was inactive.
# @TEST-EXEC: (zeek ./signal.js ./signal.zeek; echo "Shell got: $?") 1>out
# @TEST-EXEC: (zeek ./signal.js ./signal.zeek exit_only_after_terminate=T; echo "Shell got: $?") 1>out.exit_only_after_terminate
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff out.exit_only_after_terminate

@TEST-START-FILE signal.js
var sigints_handled = 0;
var kept_loop_alive = false;

zeek.on('zeek_init', () => {
  zeek.print('JS: Register SIGINT handler');
  process.on('SIGINT', () => {
    ++sigints_handled;
    zeek.print(`JS: Handling SIGINT ${sigints_handled}`);
    zeek.invoke('schedule_sigint');
  });
});

zeek.on('send_sigint', () => {
  zeek.print('JS: Sending SIGINT');
  process.kill(process.pid, 'SIGINT');
});

// Get the ball rolling.
setTimeout(() => {
  zeek.invoke('schedule_sigint');
}, 10);

// Schedule a timer to keep the Node.js loop alive until
// enough signals were processed.
process.on('beforeExit', (code) => {
  if ( sigints_handled < 5 ) {
    kept_loop_alive = true;
    setTimeout(() => { }, 0.5);
  }
});

zeek.on('zeek_done', () => {
  zeek.print(`JS: zeek_done kept_loop_alive=${kept_loop_alive}`);
});
@TEST-END-FILE

@TEST-START-FILE signal.zeek
global send_sigint: event();

global sigints_scheduled = 0;

# Hook to schedule send_sigint().
hook schedule_sigint() {
  ++sigints_scheduled;

  if ( sigints_scheduled <= 5 ) {
    print "ZEEK: schedule_sigint() hook", sigints_scheduled;
    schedule 1msec { send_sigint() };
    return;
  }

  print("ZEEK: Invoking terminate()");
  terminate();
}

event force_terminate() {
  if ( zeek_is_terminating() )
    return;

  print "ZEEK: force_terminate()";
  exit(1);
}

event do_schedule_force_terminate() {
  schedule 5000msec { force_terminate() };
}

# Ensure this terminates eventually.
event zeek_init() {
  schedule 0.001msec { do_schedule_force_terminate() };
}
