'use strict';
//
// Count the number of new_connection events and keep most_recent_limit
// connections around to include in responses.
//
// Expose this information via HTTP on port 3000.
//
const http = require('http');

// Serialize BitInt as strings.
BigInt.prototype.toJSON = function() {
  return this.toString();
}

var connections_total = 0;
var most_recent_connections_limit = 5;
var most_recent_connections = []

zeek.on('new_connection', (c) => {
  console.log(`New connection ${c.id.resp_h} ${c.id.resp_p.port}`);
  connections_total++;

  most_recent_connections.push(c);
  while (most_recent_connections.length > most_recent_connections_limit)
    most_recent_connections.shift();
});

const server = http.createServer((req, res) => {
  let data = {
    'connections': {
      'total': connections_total,
      'most_recent': {
        'limit': most_recent_connections_limit,
        'count': most_recent_connections.length,
        'connections': most_recent_connections,
      }
    }
  }
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.end(JSON.stringify(data, null, 2));
}).listen(3000);
