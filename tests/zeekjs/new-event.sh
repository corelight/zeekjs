# @TEST-DOC: Hook into new_event and record the output. Might require frequent baseline updates. Run this test only on the latest versions. It's too difficult to maintain otherwise.
# @TEST-REQUIRES: zeek --version >&2 && zeek -e 'exit(Version::info$commit >= 559 ? 0 : 1)'
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap ./new-event.js | grep -v -F '"type_name"'
# @TEST-EXEC: btest-diff .stdout
# @TEST-GROUP: smoke

@TEST-START-FILE new-event.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}

// Only include events included here.
const s = new Set([
  "connection_state_remove",
  "dns_message",
  "dns_request",
  "get_file_handle",
  "http_header",
  "http_message_done",
  "http_request",
  "new_connection",
  "ssl_established",
  "ssl_extension",
  "ssl_plaintext_data",
  "zeek_done",
  "zeek_init",
]);

zeek.on('new_event', function(name, args) {
  if (!s.has(name))
    return;
  zeek.print(`${name} ${JSON.stringify(args, null, 2)}`);
});
@TEST-END-FILE
