# @TEST-DOC: Run a unix socket echo service and client using two separate zeek processes.
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: btest-diff .stdout
set -ux
export TESTCWD=$(pwd)

(mkdir .background && cd .background && btest-bg-run zeek-unix zeek 'exit_only_after_terminate=T' ${TESTCWD}/unix-server.js)

zeek ./unix-client.js exit_only_after_terminate=T
res=$?

(cd .background && btest-bg-wait 1)

exit $res

@TEST-START-FILE unix-server.js
const net = require('net');

const socket_path = `${process.env.TESTCWD}/mysocket`;

var counter = 0;

const server = net.createServer(function(client) {
  ++counter;
  const this_client = counter;
  client.on('data', function(data) {
    console.log(`Got data ${data} from ${this_client}`);
    client.write(`echo: ${data}`);
  });
});

server.listen(socket_path, function() {
  console.log(`Listening on ${socket_path}`);
});
@TEST-END-FILE

@TEST-START-FILE unix-client.js
const net = require('net');

const socket_path = `${process.env.TESTCWD}/mysocket`;

var counter = 0;

const makeConnection = () => {
  ++counter;
  console.log(`Connecting ${counter}`);
  const this_counter = counter;
  const s = new net.Socket();
  s.on("connect", function() {
    console.log(`Connected ${this_counter}`);
    s.write(`Hello, I am ${this_counter}!`);
  });
  s.on("data", function(data) {
    console.log(`Got ${data}`);
    s.destroy();
    if ( counter == 30 ) {
      zeek.invoke("terminate");
    } else {
      console.log("Schedule next connection");
      setTimeout(makeConnection, 13);
    }
  });

  s.connect(socket_path);
};

setTimeout(makeConnection, 13);
setTimeout(() => {
  console.error('Test did not finish in time - exit 1');
  process.exit(1);
}, 3000);

@TEST-END-FILE
