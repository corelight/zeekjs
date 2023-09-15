# @TEST-DOC: package.json with {"type": "module"} caused us to run the UV IO loop during InitPostScript() indefinitely.
# @TEST-PORT: HTTP_SERVER_PORT
# @TEST-EXEC: zeek ./http.js ./http.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE package.json
{"type": "module"}
@TEST-END-FILE

@TEST-START-FILE http.js
const http = require('http');

// Safety guard.
setTimeout(() => {
    console.error('forcing exit(1)');
    process.exit(1);
}, 5000);

const server = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.end(JSON.stringify({msg: 'Got it'}));
}).listen(parseInt(process.env.HTTP_SERVER_PORT), '127.0.0.1');

zeek.on('zeek_init', () => {
    zeek.print('JS: Calling terminate');
    zeek.invoke('terminate');
});

@TEST-END-FILE

@TEST-START-FILE http.zeek
event zeek_init() &priority=10 {
  print("ZEEK: zeek_init()");
}
@TEST-END-FILE
