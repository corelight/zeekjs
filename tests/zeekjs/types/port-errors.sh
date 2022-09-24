# @TEST-DOC: Test some error cases converting Javascript into Zeek types
# @TEST-EXEC: zeek ./port.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE port.js

zeek.on('zeek_init', () => {
  console.log('Non object as port');
  try {
     zeek.invoke('is_tcp_port', [123]);
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }

  console.log('Non object as port');
  try {
     zeek.invoke('is_tcp_port', ['123']);
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }

  console.log('Empty object as port');
  try {
     zeek.invoke('is_tcp_port', [{}]);
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }

  console.log('Missing port property');
  try {
     zeek.invoke('is_tcp_port', [{'proto': 'tcp'}]);
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }

  console.log('Wrong type for port property');
  try {
     zeek.invoke('is_tcp_port', [{'port': 'abc', 'proto': 'tcp'}]);
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }

  console.log('Wrong type for proto property');
  try {
     zeek.invoke('is_tcp_port', [{'port': 1234, 'proto': 1234}]);
  } catch (error) {
    console.log(`Caught it: ${error}`);
  }
});
@TEST-END-FILE
