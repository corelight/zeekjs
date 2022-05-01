'use strict';
const fs = require('fs');

// Render BigInt (count) types as strings in JSON.
BigInt.prototype.toJSON = function() {
  return this.toString();
}

zeek.hook('Log::log_stream_policy', {priority: -1000}, function(rec, log_id) {
  // Conn::Info to Conn, PacketFilter::Info to PacketFilter
  if (log_id.includes('::'))
    [log_id] = log_id.split('::')

  // CamelCase to snake_case: PacketFilter to packet_filter
  log_id = log_id.replace(/([a-z0-9])([A-Z])/g, '\$1_\$2').toLowerCase()

  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG)
  const flat_rec = zeek.flatten(log_rec)

  // Write to the log file. Synchronous here for simplicity.
  fs.appendFileSync(log_id + '.log', JSON.stringify(flat_rec) + '\n')

  // If you wanted to hand-off logs to a central Redis server.
  // redis_client.publish(log_id, JSON.stringify(flat_rec))

  // Returning false from a hook handler is semantically the same as
  // break in Zeekscript. Not returning or returning anything else
  // has no effect in a hook handler.
  return false
})
