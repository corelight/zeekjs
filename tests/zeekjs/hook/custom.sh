# @TEST-DOC: Hooking in Javascript and propgation of "break / return false" to Zeek
# @TEST-EXEC: zeek ./hook.zeek ./hook.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE hook.js
var counter = 0;
zeek.hook('Test::my_hook', function() {
  zeek.print(`[JS] ${counter}: Hook invoked with ${JSON.stringify(arguments)}`);
  counter++;
  if (counter > 2) {
    return false;
  }
  return 42;
});

@TEST-END-FILE

@TEST-START-FILE hook.zeek
module Test;
export {
  global my_hook: hook(s: string);
}

event zeek_init() {
  local tries: vector of string = {"first", "second", "third", "fourth"};
  for (i in tries)
    print(fmt("[ZEEK] %s=%s", tries[i], hook Test::my_hook(tries[i])));
}
@TEST-END-FILE
