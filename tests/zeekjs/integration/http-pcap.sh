# @TEST-DOC: Run a http server receiving log records exported during pcap reading.
# @TEST-REQUIRES: zeek -e 'global_ids()["Log::log_stream_policy"]'
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: btest-diff http-export.log
# @TEST-EXEC: grep -F 'HTTP REQUEST' .background/.stdout > http-server.log
# @TEST-EXEC: btest-diff http-server.log
set -ux
CWD=$(pwd)

(mkdir .background && cd .background && btest-bg-run zeek-http zeek ${CWD}/http-server.js)

zeek --pseudo-realtime -r $TRACES/dns-http-https.pcap ./http-export.js | tee -a http-export.log
res=$?

(cd .background && btest-bg-wait 1)

exit $res

@TEST-START-FILE http-server.js
const http = require('http');

var counter = 0;

const server = http.createServer((req, resp) => {
  console.log(`HTTP REQUEST [${counter}] ${req.method} ${req.url}`);
  resp.end('Thanks!\n');
});

server.listen(3000);
@TEST-END-FILE

@TEST-START-FILE http-export.js
const http = require('http');

BigInt.prototype.toJSON = function() {
  return this.toString();
}

var counter = 0;

function sendit(rec) {
  ++counter;
  const request_id = counter;
  console.log(`SENDING [${request_id}] request ${rec._log_id}`);
  const url = new URL(`http://localhost:3000/${rec._log_id}`);
  const options = {
    method: 'POST',
  };

  const req = http.request(url, options, (res) => {
    res.on('end', () => { });
  });
  req.on('error', (err) => {
    console.error(`ERROR [${request_id}] ${err}`);
    process.exit(2);
  });

  req.write(JSON.stringify(rec));
  req.end();
}

zeek.hook('Log::log_stream_policy', {priority: -1000}, function(rec, log_id) {
  if (log_id.includes('::'))
    [log_id] = log_id.split('::')

  log_id = log_id.replace(/([a-z0-9])([A-Z])/g, '\$1_\$2').toLowerCase()
  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG)
  const flat_rec = zeek.flatten(log_rec)
  flat_rec._log_id = log_id;

  sendit(flat_rec);

  return false;
});
@TEST-END-FILE
