# @TEST-DOC: Port type is wrapped and overwrites toJSON to not include proto.
# @TEST-EXEC: zeek ./port-type.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE port-type.js
zeek.on('zeek_init', function() {
  let port = zeek.invoke('to_port', ['80/tcp']);
  console.log(`port=${port.port}`);
  console.log(`proto=${port.proto}`);
  console.log(`JSON.stringify=${JSON.stringify(port)}`);
});
@TEST-END-FILE
