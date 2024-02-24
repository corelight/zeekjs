# @TEST-DOC: Read udp_content_ports via zeek.global_vars['udp_content_ports']
# @TEST-EXEC: zeek global-vars.js global-vars.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE global-vars.js
zeek.on('zeek_init', function() {
  console.log(`JS: gstr=${zeek.global_vars["gstr"]}`);

  zeek.global_vars["gstr"] = "modified gstr";

  console.log(`JS: gstr=${zeek.global_vars["gstr"]}`);
});
@TEST-END-FILE

@TEST-START-FILE global-vars.zeek
export {
    global gstr = "initial gstr";
}

event zeek_done() {
    print fmt("ZEEK: zeek_done gstr=%s", gstr);
}
@TEST-END-FILE
