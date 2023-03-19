# @TEST-DOC: Hook Log::log_stream_policy and return an explicit false to break (and stop creating http.log)
# @TEST-REQUIRES: zeek -e 'global_ids()["Log::log_stream_policy"]'
# @TEST-EXEC: zeek -r $TRACES/dns.pcap ./hook.js ./local.zeek
# These aren't written because our hook log_stream_policy hook prevents it.
# @TEST-EXEC: test ! -f conn.log
# @TEST-EXEC: test ! -f dns.log
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE hook.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}

zeek.hook('Log::log_stream_policy', { priority: -1000 }, function(rec, id) {

  // Skip packet_filter, it is not using network time.
  if (id.startsWith("PacketFilter"))
    return;

  // Normalize the log names.
  if (id.includes('::'))
    [name] = id.split('::')

  name = name.replace(/([a-z][A-Z])/g, ' $1')
  name = name.toLowerCase().trim(' ').split(' ').join('_');
  rec = zeek.flatten(zeek.select_fields(rec, zeek.ATTR_LOG));
  console.log(`${name}: ${JSON.stringify(rec)}`);

  // Explicit return false means "break"
  return false;
});
@TEST-END-FILE

@TEST-START-FILE local.zeek
# Keep local_nets empty with Zeek 6.0 or later.
@ifdef ( Site::private_address_space_is_local )
redef Site::private_address_space_is_local = F;
@endif
@TEST-END-FILE
