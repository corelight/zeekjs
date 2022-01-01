# @TEST-DOC: Can Javascript disable a stream?
# @TEST-EXEC: zeek ./disable-stream.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE disable-stream.js
zeek.on('zeek_init', function() {
  let disable_result = zeek.invoke('Log::disable_stream', ['Conn::LOG']);
  console.log(`[JS] Log::disable_stream result=${disable_result}`);
});
@TEST-END-FILE
