# @TEST-DOC: Invoke zeek_version in Zeek, pass it over to Javascript and ensure it gets the same version using zeek.invoke().
# @TEST-EXEC: zeek ./check-version.zeek ./check-version.js
# @TEST-EXEC: btest-diff .stdout
# @TEST-GROUP: smoke

@TEST-START-FILE ./check-version.js
// check_version handler, invoked by Zeek.
zeek.on('Test::check_version', (expected_version) => {
  let version1 = zeek.invoke("zeek_version");
  let version2 = zeek.invoke("zeek_version", []);

  if (version1 !== expected_version) {
    console.log(`Unexpected version: JS=${version} Zeek=${expected_version}`);
  } else {
    console.log('GOOD: queried version same as expected expected')
  }

  if (version1 !== version2) {
    console.log(`Unexpected version1={version1} version2={version2}`)
  } else {
    console.log('GOOD: version1 and version2 match')
  }
});
@TEST-END-FILE

@TEST-START-FILE check-version.zeek
module Test;

export {
  global Test::check_version: event(version: string);
}

event zeek_init() {
  local expected_version = zeek_version();
  event Test::check_version(expected_version);
}
@TEST-END-FILE
