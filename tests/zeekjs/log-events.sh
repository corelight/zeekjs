# @TEST-DOC: Basic testing of the common log_ events from the base scripts
# Only run this test on the (dev) version. It's too difficult to maintain it otherwise.
# @TEST-REQUIRES: zeek --version >&2 && zeek -e 'exit((Version::info$version_number >= 80100 && Version::info$commit >= 920) ? 0 : 1)'
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap ./log-events.js ./local.zeek
# @TEST-EXEC: btest-diff .stdout

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
  const log_rec = zeek.flatten(zeek.select_fields(rec, zeek.ATTR_LOG));
  zeek.print(`DNS::log_dns: ${JSON.stringify(log_rec, null, 2)}`);
});

zeek.on('HTTP::log_http', function(rec) {
  const log_rec = zeek.flatten(zeek.select_fields(rec, zeek.ATTR_LOG));
  zeek.print(`HTTP::log_http: ${JSON.stringify(log_rec, null, 2)}`);
});

zeek.on('SSL::log_ssl', function(rec) {
  const log_rec = zeek.flatten(zeek.select_fields(rec, zeek.ATTR_LOG));
  zeek.print(`SSL::log_ssl: ${JSON.stringify(log_rec, null, 2)}`);
});
@TEST-END-FILE

@TEST-START-FILE local.zeek
# Keep local_nets empty with Zeek 6.0 or later.
@ifdef ( Site::private_address_space_is_local )
redef Site::private_address_space_is_local = F;
@endif

# Don't log ip_proto - use IP::protocol_names as indicator
# if Conn::Info$ip_proto exists.
@ifdef ( IP::protocol_names )
@load policy/protocols/conn/disable-unknown-ip-proto-support
@endif

# Do not log conn_id's ctx field here
@ifdef ( conn_id_ctx )
redef record conn_id$ctx -= { &log };
@endif
@TEST-END-FILE
