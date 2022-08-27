# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js

zeek.on('zeekjs_test_string', function(test_name, s) {
  let buf = Uint8Array.from(s, (c) => c.charCodeAt(0));
  console.log(`string ${test_name} typeof=${typeof(s)} s.length=${s.length} json=${JSON.stringify({"s": s})} buf=${buf}`);
});
@TEST-END-FILE


@TEST-START-FILE emit-events.zeek
global zeekjs_test_string: event(test_name: string, s: string);

event zeek_init() {
  event zeekjs_test_string("empty-string", "");
  event zeekjs_test_string("binary-stuff", "\x00\x01\x02\x03\x00\x00\xfd\xfe\xff");
  event zeekjs_test_string("abc", "abc");
  event zeekjs_test_string("null-bytes-1", "a\x00b");
  event zeekjs_test_string("null-bytes-2", "\x00a\x00b\x00");
  event zeekjs_test_string("null-bytes-3", "\x00\x00\x00\x00");
  event zeekjs_test_string("german", "g\xe4n");
  # Not sure we're doing the right thing here. I believe this is just
  # sending binary UTF-8 over to Javascript which then interprets it
  # as latin1 and makes a total mess out of it. This upsets btest.
  event zeekjs_test_string("german", "gänßefüßchen");
}
@TEST-END-FILE
