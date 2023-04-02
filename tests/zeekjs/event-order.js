# @TEST-DOC: Ensure output is the same between Zeek/Javascript
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap ./order.js | tee -a js-output
# @TEST-EXEC: zeek -r $TRACES/dns-http-https.pcap ./order.zeek | tee -a zeek-output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff js-output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff zeek-output
# @TEST-EXEC: diff ./js-output ./zeek-output >&2

@TEST-START-FILE order.js
zeek.on('zeek_init', function() {
  zeek.print('zeek_init');
});

zeek.on('network_time_init', function() {
  zeek.print(`network_time_init ${zeek.invoke("network_time")}`);
});

zeek.on('new_connection', function(c) {
  zeek.print(`new_connection ${c.uid}`);
});

zeek.on('connection_state_remove', function(c) {
  zeek.print(`connection_state_remove ${c.uid}`);
});

zeek.on('Conn::log_conn', function(rec) {
  zeek.print(`Conn::log_conn ${rec.uid} ${rec.service}`);
});

zeek.on('Pcap::file_done', function(path) {
  zeek.print(`Pcap::file_done ${path}`);
});

zeek.on('zeek_done', function() {
  zeek.print('zeek_done');
});

@TEST-END-FILE

@TEST-START-FILE order.zeek
event zeek_init() {
  print "zeek_init";
}

event network_time_init() {
  print fmt("network_time_init %s", network_time());
}

event new_connection(c: connection) {
  print fmt("new_connection %s", c$uid);
}

event connection_state_remove(c: connection) {
  print fmt("connection_state_remove %s", c$uid);
}

event Conn::log_conn(rec: Conn::Info) {
  print fmt("Conn::log_conn %s %s", rec$uid, rec$service);
}

event Pcap::file_done(path: string) {
  print fmt("Pcap::file_done %s", path);
}

event zeek_done() {
  print "zeek_done";
}
@TEST-END-FILE
