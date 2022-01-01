# @TEST-DOC: Hook Log::log_stream_policy and return an explicit false to break (and stop creating http.log)
# @TEST-REQUIRES: zeek -e 'global_ids()["Log::log_stream_policy"]'
# @TEST-EXEC: zeek -r $TRACES/dns.pcap ./hook.js LogAscii::use_json=T
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dns.log

@TEST-START-FILE hook.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}

zeek.hook('Log::log_stream_policy', -1000, function(rec, id) {

  // Skip packet_filter, it is not using network time.
  if (id.startsWith("PacketFilter"))
    return;

  // Normalize the log names.
  if (id.includes('::'))
    [name] = id.split('::')

  name = name.replace(/([a-z])([A-Z])/g, '$1 $2')
  name = name.toLowerCase().trim(' ').split(' ').join('_');
  console.log(`${name}: ${JSON.stringify(rec)}`);

  // No explicit return false: Do not break.
});
@TEST-END-FILE
