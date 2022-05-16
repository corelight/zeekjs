# @TEST-DOC: Use process.on('beforeExit') to prolong running the process.
# @TEST-EXEC: timeout -k 1 5 zeek ./beforeExitKeepAlive.js; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE beforeExitKeepAlive.js
var counter = 0;
zeek.on('zeek_init', () => {
  zeek.print('JS: zeek_init');
});

zeek.on('zeek_done', () => {
  zeek.print('JS: zeek_done');
});

process.on('beforeExit', (code) => {
  if (++counter <= 2) {
    zeek.print(`JS: beforeExit() code=${code} counter=${counter}`);
    setTimeout(() => zeek.print(`Timeout ${counter}`), 10);
  }
});

process.on('exit', (code) => {
  zeek.print(`JS: exit=${code}`)
});
@TEST-END-FILE
