# @TEST-DOC: Test loading a.js located within an ESM and use import statements
# @TEST-EXEC: zeek ./a.js ./a.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE package.json
{"type": "module"}
@TEST-END-FILE

@TEST-START-FILE a.js
console.log('JS/a.js: before import')
import { add, readPackageJson } from './utils.js'
console.log('JS/a.js: after import')

zeek.on('zeek_init', {priority: 1}, () => {
  console.log(`JS/zeek_init(): add(2, 7): ${add(2, 7)}`);
  console.log(`JS/zeek_init(): readPackageJson: ${readPackageJson()}`);
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
event zeek_init() &priority=-1 {
  print("ZEEK: zeek_init()");
}
@TEST-END-FILE
