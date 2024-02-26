# @TEST-EXEC: zeek ./emit-events.zeek ./consume-events.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE consume-events.js

zeek.on('zeekjs_test_pattern', function(test_name, p) {
  console.log(`JS: ${test_name} typeof=${typeof(p)} p.length=${p.length} json=${JSON.stringify({"p": p})}`);
});

zeek.on('zeek_done', () => {
  zeek.invoke('Test::test_pattern', ["any", ".+"]);
  zeek.invoke('Test::test_pattern', ["abcd", "a?bbc+d*$"]);
  try {
    zeek.invoke('Test::test_pattern', ["abcd", "a{1,"]);
  } catch (err) {
    console.log(`Test::test_pattern string caught: ${err}`);
  }

  try {
    zeek.invoke('Test::test_pattern', ["abcd", {}]);
  } catch (err) {
    console.log(`Test::test_pattern with object caught: ${err}`);
  }

  /* Zeek is not great at error reporting here :-(
    try {
      zeek.invoke('Test::test_pattern', ["abcd", "a{1,b"]);
    } catch (err) {
      console.log(`Test::test_pattern caught: ${err}`);
    } */
});
@TEST-END-FILE


@TEST-START-FILE emit-events.zeek
global zeekjs_test_pattern: event(test_name: string, p: pattern);

module Test;
function test_pattern(name: string, p: pattern) {
  print(fmt("ZEEK: %s: %s", name, p));
}

event zeek_init() {
  local simple = /.+/;
  event zeekjs_test_pattern("/.+/", simple);

  local concat = /a+/ & /b+/;
  event zeekjs_test_pattern("concat /a+/ + /b+/", concat);
}
@TEST-END-FILE
