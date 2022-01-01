# @TEST-DOC: Test invoking a Zeek event from Javascript land.
# @TEST-EXEC: zeek ./emitter.js ./receiver.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE emitter.js
zeek.on('zeek_init', () => {
  zeek.print('[JS] zeek_init(), invoking zeek.event');
  zeek.event('EventReceiver::event1');
  zeek.event('EventReceiver::event2', [32, "test-string"]);
  zeek.event('EventReceiver::event3', [{"ts": 1234}]);
});
@TEST-END-FILE


@TEST-START-FILE receiver.zeek
module EventReceiver;

export {

    type MyRecord: record {
      ts: time;
    };

    global event1: event();
    global event2: event(c: count, s: string);
    global event3: event(r: MyRecord);
}

# Event handler without args
event EventReceiver::event1() {
    print("[ZEEK] event1 received");
}

# Event handler with simple args
event EventReceiver::event2(c: count, s: string) {
  print(fmt("[ZEEK] event2 received c=%s s=%s", c, s));
}

event EventReceiver::event3(r: MyRecord) {
  print(fmt("[ZEEK] event3 received r=%s", r));
}

event zeek_init() &priority=-1 {
  print("[ZEEK] zeek_init()");

}
@TEST-END-FILE
