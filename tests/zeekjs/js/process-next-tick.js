/*
 * @TEST-DOC: Does process next tick work?
 * @TEST-EXEC: zeek %INPUT
 * @TEST-EXEC: btest-diff .stdout
 */
function immediate3() {
  console.log("immedidate3");
}

function immediate2() {
  console.log("immedidate2");
}

function nexttick2() {
  console.log("nexttick2");
}

function nexttick1() {
  console.log("nexttick1");
  process.nextTick(nexttick2);
  setImmediate(immediate3);
}

function immediate1() {
  console.log("immedidate1");
  setImmediate(immediate2);
}

function timer1() {
  console.log("timer1");
  setImmediate(immediate1);
  process.nextTick(nexttick1);
}

setTimeout(timer1, 100);
