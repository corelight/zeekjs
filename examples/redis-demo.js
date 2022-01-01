"use strict";
const redis = require('redis');

let client = redis.createClient();
client.on("error", function(error) {
  console.log(`-- redis error ${error}`);
});


zeek.on("Conn::log_conn", function(rec) {
  client.publish("conn_logs", JSON.stringify(rec), () => { console.log(`-- Conn publish done for ${rec.uid}`); });
});

zeek.on("DNS::log_dns", function(rec) {
  client.publish("dns_logs", JSON.stringify(rec), () => { console.log(`-- DNS publish done for ${rec.query}`); });
});

zeek.on("HTTP::log_http", function(rec) {
  client.publish("http_logs", JSON.stringify(rec), () => { console.log(`-- HTTP publish done for ${rec.method} ${rec.host}`); });
});

zeek.on("SSL::log_ssl", function(rec) {
  client.publish("ssl_logs", JSON.stringify(rec), () => { console.log(`-- SSL publish done for ${rec.server_name} ${rec.version}`); });
});
