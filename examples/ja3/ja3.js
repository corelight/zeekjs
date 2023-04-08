/*
 * Re-implementation of Salesforce's JA3/JA3s hash in JavaScript for Zeek.
 *
 * https://github.com/salesforce/ja3/
 */
"use strict";
const crypto = require('crypto');

const grease = new Set([
  2570n,
  6682n,
  10794n,
  14906n,
  19018n,
  23130n,
  27242n,
  31354n,
  35466n,
  39578n,
  43690n,
  47802n,
  51914n,
  56026n,
  60138n,
  64250n,
]);

/*
 * ja3
 */
const conn_ssl_exts = new Map();
const conn_ssl_ec_point_formats = new Map();
const conn_ssl_curves = new Map();

zeek.on('ssl_extension', (c, is_orig, code, val) => {
  if ( ! is_orig )
    return;

  if ( grease.has(code) )
    return;

  let uid = c.uid;

  var exts = conn_ssl_exts.get(uid);
  if ( exts === undefined ) {
    exts = [];
    conn_ssl_exts.set(uid, exts);
  }

  exts.push(code);
});

zeek.on('ssl_extension_ec_point_formats', (c, is_orig, point_formats) => {
  if ( ! is_orig )
    return;

  let fmts = []
  for ( const format of point_formats ) {
    if ( grease.has(format) )
      continue;

    fmts.push(format);
  }

  conn_ssl_ec_point_formats.set(c.uid, fmts);
});

zeek.on('ssl_extension_elliptic_curves', (c, is_orig, curves) => {
  if ( ! is_orig )
    return;

  let non_grease = [];
  for ( const curve of curves ) {
    if ( grease.has(curve) )
      continue;

      non_grease.push(curve);
  }

  conn_ssl_curves.set(c.uid, non_grease);
});

zeek.on('ssl_client_hello', (c, version, record_version, possible_ts,
                             client_random, session_id, ciphers) => {
  let uid = c.uid;
  let ja3_parts = [
    version,
    ciphers.join('-'),
    (conn_ssl_exts.get(uid) || []).join('-'),
    (conn_ssl_curves.get(uid) || []).join('-'),
    (conn_ssl_ec_point_formats.get(uid) || []).join('-'),
  ];

  let ja3_string = ja3_parts.join(',');
  let tlsfp_1 = crypto.createHash('md5').update(ja3_string).digest('hex');

  c.ssl.js_ja3 = tlsfp_1;

  conn_ssl_exts.delete(uid);
  conn_ssl_curves.delete(uid);
  conn_ssl_ec_point_formats.delete(uid);
});

/*
 * ja3s
 */
const ja3s_conn_ssl_exts = new Map();

zeek.on('ssl_extension', (c, is_orig, code, val) => {
  if ( is_orig )
    return;

  let uid = c.uid;
  var exts = [];

  var exts = ja3s_conn_ssl_exts.get(uid);
  if ( exts === undefined ) {
    exts = [];
    ja3s_conn_ssl_exts.set(uid, exts);
  }
  exts.push(code);
});

zeek.on('ssl_server_hello', (c, version, record_version, possible_ts,
                             server_random, session_id, cipher, comp_method) => {
  let uid = c.uid;
  let ja3s_parts = [
    version,
    cipher,
    (ja3s_conn_ssl_exts.get(uid) || []).join('-'),
  ];

  let ja3s_string = ja3s_parts.join(',');
  let ja3sfp_1= crypto.createHash('md5').update(ja3s_string).digest('hex');

  c.ssl.js_ja3s = ja3sfp_1;

  ja3s_conn_ssl_exts.delete(uid);
});
