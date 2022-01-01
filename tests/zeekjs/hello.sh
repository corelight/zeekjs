# @TEST-EXEC: zeek ./hello.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE hello.js
zeek.on('zeek_init', function() {
  zeek.print("hello");
});

@TEST-END-FILE
