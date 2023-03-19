# @TEST-DOC: Run a http server and client using two separate zeek processes. Expect 100 requests to take less than a few seconds.
# @TEST-PORT: HTTP_SERVER_PORT
# @TEST-EXEC: bash %INPUT
set -ux
CWD=$(pwd)

(mkdir .background && cd .background && btest-bg-run zeek-http zeek 'exit_only_after_terminate=T' ${CWD}/http-server.js)

zeek ./http-client.js exit_only_after_terminate=T >&2
res=$?

(cd .background && btest-bg-wait 1)

exit $res

@TEST-START-FILE http-server.js
const http = require('http');

var counter = 0;

const server = http.createServer((req, resp) => {
  ++counter;
  resp.end(`${counter}\n`);
});

server.listen(parseInt(process.env.HTTP_SERVER_PORT), '127.0.0.1');
@TEST-END-FILE

@TEST-START-FILE http-client.js
const http = require('http');

var counter = 1;

const url = new URL(`http://127.0.0.1:${parseInt(process.env.HTTP_SERVER_PORT)}`);

const makeRequest = () => {
  console.log(`making request - ${counter}`);
  const req = http.request(url, (res) => {
    console.log(`Got response: ${res.statusCode}`);
    res.on('data', (chunk) => {
      chunk = chunk.toString().trim();
      const n = parseInt(chunk);
      console.log(`chunk=${chunk} n=${n} counter=${counter}`);
      ++counter;
      if (counter === 100) {
        zeek.invoke('terminate');
      } else {
        setTimeout(makeRequest, 13);
      }
    });
  });
  req.on('error', (err) => {
    console.error(`Request error: ${err}`);
    process.exit(2);
  });

  req.end();
};

setTimeout(makeRequest, 13);
setTimeout(() => {
  console.error('Test did not finish in time - exit 1');
  process.exit(1);
}, 5000);

@TEST-END-FILE
