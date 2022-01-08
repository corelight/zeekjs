'use strict';
const fs = require('fs');

// Render BigInt (count) types as strings in JSON.
BigInt.prototype.toJSON = function() {
  return this.toString();
}

zeek.hook('Log::log_stream_policy', -1000, function(rec, log_id) {
  // Conn::Info to Conn, PacketFilter::Info to PacketFilter
  if (log_id.includes('::'))
    [log_id] = log_id.split('::')

  // CamelCase to snake_case: PacketFilter to packet_filter
  log_id = log_id.replace(/([a-z0-9])([A-Z])/g, '\$1_\$2').toLowerCase()

  // Copy the log record to make it mutable.
  let copy = Object.assign({}, rec);

  // Replace {"orig_p": {"port": <port> "proto": ...}} with {"orig_p": <port>}
  if (copy.id?.orig_p?.port !== undefined) {
    copy.id = Object.assign({}, rec.id);  // Copy the id record to mutate it.
    copy.id['orig_p'] = rec.id.orig_p.port;
    copy.id['resp_p'] = rec.id.resp_p.port;
  }

  // Write to a the log file. Synchronous here for simplicity.
  fs.appendFileSync(log_id + '.log', JSON.stringify(copy) + '\n')

  // If you wanted to hand-off logs to a central Redis server.
  // redis_client.publish(log_id, JSON.stringify(copy));

  // Returning false from a hook handler is semantically the same as
  // break in Zeekscript. Not returning or returning anything else
  // has no effect in a hook handler.
  return false;
});
