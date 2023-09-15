# @TEST-DOC: Check error handling for bad events.
# @TEST-EXEC: zeek ./emitter.js ./receiver.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE emitter.js
zeek.on('zeek_init', () => {
  try {
    zeek.event('EventReceiver::unknown');
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.event('EventReceiver::event1', 0);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.event('EventReceiver::event1', []);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.event('EventReceiver::event1', [0]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

  try {
    zeek.event('EventReceiver::event1', ["a", "b"]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`);
  }

});
@TEST-END-FILE


@TEST-START-FILE receiver.zeek
module EventReceiver;

export {
    global event1: event(s: string);
}

event EventReceiver::event1(s: string) {
    print("[ZEEK] event1 received");
}
@TEST-END-FILE
