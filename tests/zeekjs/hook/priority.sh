# @TEST-DOC: Basic testing of whether hooks with priorities are working using DNS::log_policy
# @TEST-EXEC: zeek -r $TRACES/dns.pcap ./priority.js ./priority.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE priority.js
zeek.hook('DNS::log_policy', { priority: -10 }, () => { zeek.print('[JS] DNS::log_policy: -10'); })
zeek.hook('DNS::log_policy', { priority: 10 }, () => { zeek.print('[JS] DNS::log_policy: 10'); })
@TEST-END-FILE


@TEST-START-FILE priority.zeek
hook DNS::log_policy(rec: DNS::Info, id: Log::ID, f: Log::Filter) &priority=-9 {
  print("[ZEEK] DNS::log_policy: -9");
}
hook DNS::log_policy(rec: DNS::Info, id: Log::ID, f: Log::Filter) &priority=1 {
  print("[ZEEK] DNS::log_policy: 1");
}
hook DNS::log_policy(rec: DNS::Info, id: Log::ID, f: Log::Filter) &priority=11 {
  print("[ZEEK] DNS::log_policy: 11");
}
@TEST-END-FILE
