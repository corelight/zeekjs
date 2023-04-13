/* Redis exporter using Log::log_stream_policy hook and Redis's pub/sub */
const redis = require('redis');

BigInt.prototype.toJSON = function() {
  return this.toString();
}

const client = redis.createClient();
client.connect();

zeek.hook('Log::log_stream_policy', (rec, stream_id) => {
  if ( ! client.isReady )  // Short-cut: not yet connected, just drop the record.
    return;

  let log_rec = zeek.select_fields(rec, zeek.ATTR_LOG);
  let data = JSON.stringify(log_rec);
  client.publish(stream_id, JSON.stringify(log_rec));
});
