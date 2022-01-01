# @TEST-DOC: Should raise an exception if the enum is not known.
# @TEST-EXEC: zeek ./disable-stream.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE disable-stream.js
zeek.on('zeek_init', function() {
  try {
    zeek.invoke('Log::disable_stream', ['UnknownZeekJS::LOG']);
  } catch (error) {
    console.log(`Caught it: ${error}`)
  }
});
@TEST-END-FILE
