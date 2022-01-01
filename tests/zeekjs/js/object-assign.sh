# @TEST-DOC: Ensure that Object.assign() works on our proxy objects.
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap ./assign.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE assign.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}
zeek.on('zeek_done', function() {
  let nstats = zeek.invoke('get_net_stats')
  console.log(JSON.stringify(nstats));
  let nstats_copy = Object.assign({}, nstats);
  console.log(JSON.stringify(nstats_copy));
});
@TEST-END-FILE
