# @TEST-DOC: Is beforeExit invoked?
# @TEST-EXEC: timeout -k 1 5 zeek ./beforeExit.js; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE beforeExit.js
zeek.on('zeek_init', () => {
  zeek.print('JS: zeek_init');
});

zeek.on('zeek_done', () => {
  zeek.print('JS: zeek_done');
});

process.on('beforeExit', (code) => {
  zeek.print(`JS: beforeExit() code=${code}`);
});

process.on('exit', (code) => {
  zeek.print(`JS: exit=${code}`)
});
@TEST-END-FILE
