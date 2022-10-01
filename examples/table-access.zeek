@load ./table-access.js

module Test;

export {
  type Entry: record {
    name: string;
  };

  global ip_map: table[addr] of Entry;
}

event connection_state_remove(c: connection) {
  print fmt("ZEEK: JS told us about about %s IPs %s", |ip_map|, ip_map);
}
