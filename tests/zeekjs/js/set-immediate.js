/*
 * @TEST-DOC: Test setTimer() and setImmediate() functioning
 * @TEST-EXEC: zeek %INPUT
 * @TEST-EXEC: btest-diff .stdout
 */
function timer2() {
  console.log("timer2");
}

function immediate3() {
  console.log("immedidate3");
  setTimeout(timer2, 10);
}
function immediate2() {
  console.log("immedidate2");
  setImmediate(immediate3);
}

function immediate1() {
  console.log("immedidate1");
  setImmediate(immediate2);
}

function timer1() {
  console.log("timer1");
  setImmediate(immediate1);
}

setTimeout(timer1, 100);
