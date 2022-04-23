# @TEST-DOC: Basic testing of whether priority is working using zeek_init and dns_request
# @TEST-EXEC: zeek -r $TRACES/dns.pcap ./priority.js ./priority.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE priority.js
zeek.on('zeek_init', { priority: -10 }, () => { zeek.print('[JS] zeek_init: -10'); })
zeek.on('zeek_init', {priority: 10 }, () => { zeek.print('[JS] zeek_init: 10'); })
zeek.on('zeek_init', () => { zeek.print('[JS] zeek_init: 0 (default)'); })

zeek.on('dns_request', function(c, msg, query, qtype, qclass) {
  zeek.print(`[JS] dns_request: 0 (default) ${query}`);
});

zeek.on('dns_request', { priority: 10 }, function(c, msg, query, qtype, qclass) {
  zeek.print(`[JS] dns_request: 10 ${query}`);
});
@TEST-END-FILE


@TEST-START-FILE priority.zeek
event zeek_init() &priority=-9 { print("[ZEEK] zeek_init: -9"); }
event zeek_init() &priority=1 { print("[ZEEK] zeek_init: 1"); }
event zeek_init() &priority=11 { print("[ZEEK] zeek_init: 11"); }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=11 {
  print(fmt("[ZEEK] dns_request: 11 %s", query));
}
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=-1 {
  print(fmt("[ZEEK] dns_request: -1 %s", query));
}
@TEST-END-FILE
