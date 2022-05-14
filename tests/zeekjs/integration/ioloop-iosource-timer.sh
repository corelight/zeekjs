# @TEST-DOC: Scheduling a timer in Javascript extends lifetime
# @TEST-EXEC: timeout -k 1 5 zeek ./exit.js; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE exit.js
setTimeout(() => {
  zeek.print('Timer expires');
}, 1000);
@TEST-END-FILE exit.js
