# @TEST-DOC: Run a udp socket echo service and client using two separate zeek processes.
# @TEST-EXEC: bash %INPUT
# @TEST-PORT: PORT
# @TEST-EXEC: btest-diff .stdout
set -ux
export TESTCWD=$(pwd)

(mkdir .background && cd .background && btest-bg-run zeek-udp zeek 'exit_only_after_terminate=T' ${TESTCWD}/udp-server.js)

zeek ./udp-client.js exit_only_after_terminate=T
res=$?

(cd .background && btest-bg-wait 1)

exit $res

@TEST-START-FILE udp-server.js
const udp = require('dgram');

const port = parseInt(process.env.PORT);

var counter = 0;

const server = udp.createSocket("udp4");
server.on("message", function(msg, info) {
    console.log(`Got data ${msg} from ${JSON.stringify(info)}`);
    server.send(`echo: ${msg}`, info.port, info.address, function(error) {
      if ( error !== null ) {
        console.log(`Error sending ${error}`);
        process.exit(1);
      }
    });
});

server.on("listening", function() {
  const a = server.address();
  console.log(`Listening on ${a.address}:${a.port}`);
});
server.bind(port, '127.0.0.1');
@TEST-END-FILE

@TEST-START-FILE udp-client.js
const udp = require('dgram');

const port = parseInt(process.env.PORT);

var counter = 0;

const makeConnection = () => {
  ++counter;
  console.log(`Connecting ${counter}`);
  const this_counter = counter;
  const s = udp.createSocket("udp4");
  s.on("connect", function() {
    console.log(`Connected ${this_counter}, sending...`);
    s.send(`Hello, I am ${this_counter}!`);
  });
  s.on("message", function(msg, info) {
    console.log(`Got ${msg}`);
    s.close();
    if ( counter == 30 ) {
      zeek.invoke("terminate");
    } else {
      console.log("Schedule next connection");
      setTimeout(makeConnection, 13);
    }
  });

  s.connect(port, '127.0.0.1');
};

setTimeout(makeConnection, 13);
setTimeout(() => {
  console.error('Test did not finish in time - exit 1');
  process.exit(1);
}, 3000);

@TEST-END-FILE
