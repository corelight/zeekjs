# @TEST-DOC: Javascript calling Config::set_value() for some base types
# @TEST-EXEC: zeek ./config.js ./config.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE config.js
zeek.on('zeek_init', () => {
  zeek.print('JS: changing Site::local_nets');
  zeek.invoke('Config::set_value', ['Site::local_nets', zeek.as('subnet_set', ['192.168.0.0/16', '10.0.0.0/8'])]);
});
@TEST-END-FILE

@TEST-START-FILE config.zeek
@load base/frameworks/config

# Keep local_nets empty with Zeek 6.0 or later.
@ifdef ( Site::private_address_space_is_local )
redef Site::private_address_space_is_local = F;
@endif

export {
  type subnet_set: set[subnet];
}

event zeek_done() {
  print fmt("ZEEK: zeek_done: Site::local_nets=%s", Site::local_nets);
}
@TEST-END-FILE
