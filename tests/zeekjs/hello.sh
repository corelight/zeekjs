# @TEST-EXEC: zeek ./hello.js
# @TEST-EXEC: btest-diff .stdout
# @TEST-GROUP: smoke

@TEST-START-FILE hello.js
zeek.on('zeek_init', function() {
  zeek.print("hello");
});

@TEST-END-FILE
