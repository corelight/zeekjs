# @TEST-DOC: Disable an analyzer from JS
# @TEST-REQUIRES: zeek -e 'global_ids()["analyzer_confirmation"]'
# @TEST-EXEC: zeek http.js -r $TRACES/http-pipelined-requests.pcap
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE http.js
// Keep state of connection uids to its analyzers.
var analyzers = {};

zeek.on('analyzer_confirmation', (c, atype, aid) => {
  console.log('analyzer_confirmation', c.uid, atype, aid);
  if ( analyzers[c.uid] === undefined )
    analyzers[c.uid] = {};
  analyzers[c.uid][atype] = aid;
});

zeek.on('http_request', (c, uri1, uri2, method) => {
  let aid = analyzers[c.uid]['Analyzer::ANALYZER_HTTP'];
  console.log('http_request', c.uid, uri1, uri2, method, aid);
  // Disable including prevent=true.
  zeek.invoke('disable_analyzer', [c.id, aid, true, true]);
});
@TEST-END-FILE http.js
