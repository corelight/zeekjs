# @TEST-DOC: Call network_time() and stats bifs in zeek_done after reading a pcap
# @TEST-EXEC: zeek -r $TRACES/http.pcap ./get-stats.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE get-stats.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}


zeek.on('network_time_init', () => {
  let ts = zeek.invoke('network_time');
  console.log(`network_time_init ts=${ts}`);
});

zeek.on('zeek_done', function() {
  let net_stats = zeek.invoke('get_net_stats');
  let event_stats = zeek.invoke('get_event_stats');
  console.log(JSON.stringify(net_stats, null, 2));

  console.log(`queued in event_stats ${'queued' in event_stats}`);
  console.log(`dispatched in event_stats ${'dispatched' in event_stats}`);
  console.log(`queued >= 40 ${event_stats['queued'] >= 40}`)
  console.log(`dispatched >= 40 ${event_stats['dispatched'] >= 40}`)
});
@TEST-END-FILE
