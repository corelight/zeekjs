# @TEST-DOC: Read udp_content_ports via zeek.global_vars['udp_content_ports']
# @TEST-EXEC: zeek global-vars.js global-vars.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE global-vars.js
zeek.on('zeek_init', function() {
  try {
    zeek.global_vars["cstr"] = "cannot set const";
  } catch (error) {
    console.log(`Caught it: ${error} (cstr=${zeek.global_vars["cstr"]})`);
  }

  try {
    zeek.global_vars["ostr"] = "cannot set option";
  } catch (error) {
    console.log(`Caught it: ${error} (ostr=${zeek.global_vars["ostr"]})`);
  }

  try {
    zeek.global_vars["R"] = "cannot set type";
  } catch (error) {
    console.log(`Caught it: ${error} (R=${zeek.global_vars["R"]})`);
  }

  try {
    zeek.global_vars["myaddr"] = "not.an.addr";
  } catch (error) {
    console.log(`Caught it: ${error} (myaddr=${zeek.global_vars["myaddr"]})`);
  }
});
@TEST-END-FILE

@TEST-START-FILE global-vars.zeek
export {
    type R: record { a: string; };
    global gstr = "initial gstr";
    const cstr = "initial const";
    option ostr = "initial option";
    global myaddr = 1.1.1.1;
}
@TEST-END-FILE
