# @TEST-DOC: Call suspend_processing() and continue_processing(). This was buggy because they return nil.
# @TEST-EXEC: zeek -r $TRACES/http.pcap ./suspend-continue.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE suspend-continue.js
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}

zeek.on('zeek_init', () => {
  console.log('suspend_processing');
  zeek.invoke('suspend_processing');
  let suspended_at = Date.now();

  setTimeout(() => {
    console.log('continue_processing');
    zeek.invoke('continue_processing');
    let continued_at = Date.now();
    console.log(`delayed enough? ${(continued_at - suspended_at) > 200}`);
  }, 250);

  setTimeout(() => console.log('still waiting...'), 100);
  console.log('zeek_init end');
});

zeek.on('Pcap::file_done', (path) => {
  let net_stats = zeek.invoke('get_net_stats');
  console.log(JSON.stringify(net_stats, null, 2));
});

zeek.on('zeek_done', function() {
  console.log('zeek_done');
});
@TEST-END-FILE
