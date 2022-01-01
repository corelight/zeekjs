# @TEST-DOC: Test invoking many Zeek events. This crashed with modern Node versions due to missing Isolate::Scope usage.
# @TEST-EXEC: zeek ./receiver.js ./emitter.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE receiver.js
var event1 = 0;
var event2 = 0;
zeek.on('TestEmitter::event1', (c, s) => {
  if ((event1 % 10) == 0)
    console.log(c + " " + s);
  ++event1;
});

zeek.on('TestEmitter::event2', (r) => {
  if ((event2 % 10) == 0)
    console.log("x " + JSON.stringify(r));
  ++event2;
});

zeek.on('zeek_done', () => {
  console.log(`event1=${event1} event2=${event2}`);
});
@TEST-END-FILE


@TEST-START-FILE emitter.zeek
redef exit_only_after_terminate=T;

module TestEmitter;

export {
    type MyRecord: record {
      d: double;
    };
    global event1: event(c: count, s: string);
    global event2: event(r: MyRecord);
}

global c = 0;

event TestEmitter::emit_events() {
    event TestEmitter::event1(42, "Answer");
    event TestEmitter::event2(MyRecord($d=count_to_double(c)));

    # Are we done?
    if (++c == 100) {
      terminate();
      return;
    }

    schedule 1msec { TestEmitter::emit_events() };

}
event zeek_init() &priority=-1 {
  schedule 1msec { TestEmitter::emit_events() };
}
@TEST-END-FILE
