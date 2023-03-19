# @TEST-DOC: Run a http server receiving log records exported during pcap reading.
# @TEST-PORT: HTTP_SERVER_PORT
# @TEST-REQUIRES: zeek -e 'global_ids()["Log::log_stream_policy"]'
# @TEST-EXEC: bash %INPUT
# Sort the exporter log due to timing sensitivity
# @TEST-EXEC: sort http-export.log > http-export.log.sorted
# @TEST-EXEC: btest-diff http-export.log.sorted
# @TEST-EXEC: grep -F 'HTTP REQUEST' .background/.stdout > http-server.log
# @TEST-EXEC: btest-diff http-server.log
set -ux
CWD=$(pwd)

(mkdir .background && cd .background && btest-bg-run zeek-http zeek ${CWD}/http-server.js)

zeek --pseudo-realtime -r $TRACES/dns-http-https.pcap ./http-export.js exit_only_after_terminate=T | tee -a http-export.log
res=$?

(cd .background && btest-bg-wait 1)

exit $res

@TEST-START-FILE http-server.js
const http = require('http');

var counter = 0;

const server = http.createServer((req, resp) => {
  ++counter;
  const rc = counter;
  console.log(`[${rc}] HTTP REQUEST ${req.method} ${req.url}`);
  resp.end(`Thanks for request number ${rc} to ${req.url}`);
});

server.listen(parseInt(process.env.HTTP_SERVER_PORT), '127.0.0.1');
@TEST-END-FILE

# Naive HTTP exporter doing one request per log entry.
@TEST-START-FILE http-export.js
const http = require('http');

BigInt.prototype.toJSON = function() {
  return this.toString();
}

var counter = 0;

function sendit(rec) {
  ++counter;
  const request_id = counter;
  console.log(`[${request_id}] 1 SENDING request for ${rec._log_id}`);
  const url = new URL(`http://127.0.0.1:${parseInt(process.env.HTTP_SERVER_PORT)}/${rec._log_id}`);
  const options = {
    method: 'POST',
  };

  const req = http.request(url, options, (res) => {
    console.log(`[${request_id}] 2 RESULT ${res.statusCode}`);
    res.on('data', (chunk) => { console.log(`[${request_id}] 3 DATA ${chunk}`); });
    res.on('end', () => { console.log(`[${request_id}] 4 END`); });
  });
  req.on('error', (err) => {
    console.error(`[${request_id}] 0 ERROR ${err}`);
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

// Primitive keep-alive timer based on incoming packets.
// This would be nicer via net_done(), but that's not triggered
// when exit_only_after_terminate=T. Need pcap_done() or so.
var last_packet_timeout = null;
var timer = 0;
zeek.on('raw_packet', (hdr) => {
  if (last_packet_timeout !== null) {
    // console.log('JS: clearing', last_packet_timeout);
    clearTimeout(last_packet_timeout)
  }

  ++timer;
  const tt = timer;
  last_packet_timeout = setTimeout(() => {
    console.log(`[${counter}] Terminate timeout`);
    zeek.invoke('terminate');
  }, 1000);
});
@TEST-END-FILE
