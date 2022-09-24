# @TEST-DOC: Port type is wrapped and overwrites toJSON to not include proto.
# @TEST-EXEC: zeek ./port-type.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE port-type.js
zeek.on('zeek_init', function() {
  let tcp_port = zeek.invoke('to_port', ['80/tcp']);
  console.log(`tcp_port.port=${tcp_port.port}`);
  console.log(`tcp_port.proto=${tcp_port.proto}`);
  console.log(`JSON.stringify=${JSON.stringify(tcp_port)}`);
  console.log(`tcp is tcp: ${zeek.invoke('is_tcp_port', [tcp_port])}`);
  console.log(`tcp is udp : ${zeek.invoke('is_udp_port', [tcp_port])}`);

  let udp_port = zeek.invoke('to_port', ['4789/udp']);
  console.log(`udp_port.port=${udp_port.port}`);
  console.log(`udp_port.proto=${udp_port.proto}`);
  console.log(`JSON.stringify=${JSON.stringify(udp_port)}`);
  console.log(`udp is tcp: ${zeek.invoke('is_tcp_port', [udp_port])}`);
  console.log(`udp is udp : ${zeek.invoke('is_udp_port', [udp_port])}`);

});
@TEST-END-FILE
