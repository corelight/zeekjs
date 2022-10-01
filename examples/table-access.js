// Keep a reference to the Test::ip_map table on the Zeek side.
var ip_map = zeek.global_vars['Test::ip_map'];
var c = 0;

function tick() {
  ++c;
  let ip = `192.168.0.${c % 256}`;

  console.log(`JS: Setting ${ip}`);

  ip_map[ip] = {name: `js_tick_${c}`};

  setTimeout(tick, 5000);
}

setTimeout(tick, 5);
