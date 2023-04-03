# @TEST-DOC: Using the intel framework from Zeek
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap ./my-intel.zeek
# @TEST-EXEC: zeek-cut < intel.log > intel.log.noheaders
# @TEST-EXEC: btest-diff intel.log.noheaders
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE my-intel.js
zeek.on('zeek_init', () => {
  let indicators = [
    { indicator: "corelight.com", indicator_type: "Intel::DOMAIN", meta: { source: "source1" } },
    { indicator: "199.60.103.106", indicator_type: "Intel::ADDR", meta: { source: "source2" } },
  ];

  for ( const i of indicators )
    zeek.invoke('Intel::insert', [i]);
});

zeek.on('Intel::match', (s, items) => {
  let nt = zeek.invoke('network_time');
  console.log(`${nt} ${items.length} Intel::match on '${s.indicator}' in '${s.where}' for ${s.conn.uid} (${JSON.stringify(items)})`);
});
@TEST-END-FILE

@TEST-START-FILE my-intel.zeek
@load base/frameworks/intel
@load frameworks/intel/seen

@load ./my-intel.js
@TEST-END-FILE
