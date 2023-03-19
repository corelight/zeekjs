# @TEST-DOC: Run a http server, but start listening from zeek_init() only.
# @TEST-PORT: HTTP_SERVER_PORT
# @TEST-EXEC: bash %INPUT

# Server output
# @TEST-EXEC:  TEST_DIFF_CANONIFIER="grep -v '^<<<'" btest-diff .background/.stdout

# Client output
# @TEST-EXEC: btest-diff .stdout
set -ux
CWD=$(pwd)

(mkdir .background && cd .background && btest-bg-run zeek-http zeek 'exit_only_after_terminate=T' ${CWD}/http-server.js)

zeek ./http-client.js exit_only_after_terminate=T
res=$?

(cd .background && btest-bg-wait 1)

exit $res

@TEST-START-FILE http-server.js
const http = require('http');

var counter = 0;

zeek.on('zeek_init', () => {
  console.log('Starting HTTP server');
  const server = http.createServer((req, resp) => {
    ++counter;
    console.log(`Got a request counter=${counter}`);
    resp.end(`${counter}\n`);
  });

  server.listen(parseInt(process.env.HTTP_SERVER_PORT), '127.0.0.1', 100, () => {
    console.log('We are listening!');
  });
});
@TEST-END-FILE

@TEST-START-FILE http-client.js
const http = require('http');

const url = new URL(`http://127.0.0.1:${parseInt(process.env.HTTP_SERVER_PORT)}`);

const makeRequest = () => {
  console.log('Making request');
  const req = http.request(url, (res) => {
    console.log(`Got response: ${res.statusCode}`);
    res.on('data', (chunk) => {
      chunk = chunk.toString().trim();
      console.log(`Got data ${chunk}: Success!`);
      zeek.invoke('terminate');
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
