# @TEST-DOC: JavaScript using FinalizationRegistry. This was observed to hang (from on-exit-leak-free package)
# @TEST-EXEC: zeek ./finalization-registry.js; echo "Shell got: $?"
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE finalization-registry.js
'use strict'

function clear() {
  console.log("clear");
}

const registry = new FinalizationRegistry(clear);

function onExit () {
  console.log("onExit()");
}

setImmediate(() => {
  let obj = {foo: 'bar'};
  let ref = new WeakRef(obj);
  registry.register(obj, ref);
  process.on('exit', onExit);
});
@TEST-END-FILE
