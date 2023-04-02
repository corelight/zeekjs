/*
 * @TEST-DOC: Call setImmediate() very often.
 * @TEST-EXEC: zeek %INPUT
 * @TEST-EXEC: btest-diff .stdout
 */

const limit = 50;
var counter = 0;

function immediate1() {
  ++counter;
  console.log(`immediate1 counter=${counter}`);
  if ( counter < limit )
    setImmediate(immediate1);

}

zeek.on('zeek_init', () => {
  counter = 0;
  console.log('zeek_init');
  setImmediate(immediate1);
});

zeek.on('zeek_done', () => {
  counter = 0;
  console.log('zeek_done');
  setImmediate(immediate1);
});
