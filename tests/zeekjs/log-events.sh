# @TEST-DOC: Basic testing of the common log_ events from the base scripts
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap ./log-events.js
# SSL history does not exist with Zeek 4
# @TEST-EXEC: grep -v ssl_history .stdout > stdout.no_ssl_history
# @TEST-EXEC: btest-diff stdout.no_ssl_history

@TEST-START-FILE log-events.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}


zeek.on('Conn::log_conn', function(rec) {
  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG);
  zeek.print(`Conn::log_conn: ${JSON.stringify(log_rec, null, 2)}`);
});
zeek.on('DNS::log_dns', function(rec) {
  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG);
  zeek.print(`DNS::log_dns: ${JSON.stringify(log_rec, null, 2)}`);
});

zeek.on('HTTP::log_http', function(rec) {
  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG);
  zeek.print(`HTTP::log_http: ${JSON.stringify(log_rec, null, 2)}`);
});

zeek.on('SSL::log_ssl', function(rec) {
  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG);
  zeek.print(`SSL::log_ssl: ${JSON.stringify(log_rec, null, 2)}`);
});
@TEST-END-FILE
