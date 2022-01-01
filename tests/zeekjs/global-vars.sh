# @TEST-DOC: Read udp_content_ports via zeek.global_vars['udp_content_ports']
# @TEST-EXEC: zeek 'udp_content_ports += { 4000/udp, 4002/udp }' global-vars.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE global-vars.js
zeek.on('zeek_init', function() {
  console.log(`udp_content_ports=${JSON.stringify(zeek.global_vars['udp_content_ports'])}`);
});
@TEST-END-FILE
