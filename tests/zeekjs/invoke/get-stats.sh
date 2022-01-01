# @TEST-DOC: Call network_time() and stats bifs in zeek_done after reading a pcap
# @TEST-EXEC: zeek -r $TRACES/http.pcap ./get-stats.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE get-stats.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}


zeek.on('zeek_done', function() {
  let ts = zeek.invoke('network_time');
  let net_stats = zeek.invoke('get_net_stats');
  let event_stats = zeek.invoke('get_event_stats');
  console.log(`ts=${ts}`);
  console.log(JSON.stringify(net_stats, null, 2));
  console.log(JSON.stringify(event_stats, null, 2));
});
@TEST-END-FILE
