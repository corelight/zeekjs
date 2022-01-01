# @TEST-DOC: Schedule a timer via setInterval() and run it 1000 times. That blew up with a segfaults previously.
# @TEST-EXEC: zeek 'exit_only_after_terminate=T' ./timer.js ./timer.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE timer.js
var rounds = 0;

function go_around() {
  if (++rounds == 1000) {
    console.log(`We did ${rounds} rounds. Enough.`);
    zeek.invoke('terminate');
  }
}

zeek.on('zeek_init', function() {
  setInterval(go_around, 1);
});
@TEST-END-FILE

@TEST-START-FILE timer.zeek
event terminate_now() {
  if (zeek_is_terminating())
    return;

  print("ERROR: JS didn't invoke terminate() ?");
  terminate();
}
event zeek_init() {
  schedule 3sec { terminate_now() };
}
@TEST-END-FILE
