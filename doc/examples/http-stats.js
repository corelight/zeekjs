'use strict';
const http = require('http');

// Render BigInt (count) types as strings in JSON.
BigInt.prototype.toJSON = function() {
  return this.toString();
}


http.createServer((req, res) => {
  let stats = {
    net: zeek.invoke('get_net_stats'),
    event: zeek.invoke('get_event_stats'),
    zeek_version: zeek.invoke('zeek_version'),
  };
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.end(JSON.stringify(stats));
}).listen(3000);
