# @TEST-DOC: Verify that we do not report true for toJSON on objects that wrap Zeek values except for ports. Regression test for #116
#
# @TEST-EXEC: zeek -r $TRACES/http.pcap ./main.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE main.js
zeek.on('connection_state_remove', {priority: -1000}, (c) => {
  console.log('toJSON in c.id', 'toJSON' in c.conn.id);
  console.log('Object.hasOwn(c.id, toJSON)', Object.hasOwn(c.id, 'toJSON'));
  console.log('toJSON in c.id.orig_p', 'toJSON' in c.id.orig_p);
  console.log('Object.hasOwn(c.id.orig_p, toJSON)', Object.hasOwn(c.id.orig_p, 'toJSON'));
});

@TEST-END-FILE
