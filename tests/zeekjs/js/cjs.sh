# @TEST-DOC: Test loading a.cjs located within an ESM top-level dynamic import()
# @TEST-EXEC: zeek ./a.cjs ./a.zeek exit_only_after_terminate=T
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE package.json
{"type": "module"}
@TEST-END-FILE

@TEST-START-FILE a.cjs
// Asynchronously import utils, then trigger utils_imported Zeek event
// which in turn will use the utils.
//
// There's no real reason this needs to go through zeek.
var utils;
import('./utils.js').then((x) => {
  utils = x;
  console.log('utils:', x);
  zeek.event('utils_imported');
})

// utils_imported Zeek event.
zeek.on('utils_imported', () => {
  console.log(`JS/utils_imported(): utils.add(2, 7): ${utils.add(2, 7)}`);
  console.log(`JS/utils_imported(): utils.readPackageJson: ${utils.readPackageJson()}`);
  zeek.invoke('terminate');
});
@TEST-END-FILE

@TEST-START-FILE utils.js
import { readFileSync } from 'fs';
console.log('JS/utils.js: top-level')
export const add = (x, y) => {
  return x + y;
}

export const readPackageJson = () => {
  return readFileSync('package.json').toString().trim();
}
@TEST-END-FILE

@TEST-START-FILE a.zeek
# Declare the utils_imported event on the Zeek side
global utils_imported: event();

event zeek_init() {
  print("ZEEK: zeek_init()");
}
@TEST-END-FILE
