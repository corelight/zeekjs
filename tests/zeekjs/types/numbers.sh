# @TEST-DOC: Check behavior of JavaScript numbers and bigints to Zeek int or count conversion.
#
# @TEST-EXEC: zeek ./consume-events.zeek ./emit-events.js
# @TEST-EXEC: btest-diff .stdout

# @TEST-START-FILE emit-events.js
// JS number to int.
zeek.on('zeek_init', {priority: -10}, () => {
  zeek.event('want_int', ["-9223372036854775808", -(2**63)]);
  zeek.event('want_int', ["-9007199254740991", -(2**53 - 1)]);
  zeek.event('want_int', ["-4294967296", -(2**32)]);
  zeek.event('want_int', ["-2147483648", -(2**31)]);
  zeek.event('want_int', ["-1", -1]);
  zeek.event('want_int', ["0", 0]);
  zeek.event('want_int', ["42", 42]);
  zeek.event('want_int', ["2147483647", 2**31 - 1]);
  zeek.event('want_int', ["9007199254740991", (2**53) - 1]);
  // 2**63-1 as BigInt can be represented as a Zeek int
  zeek.event('want_int', ["9223372036854775807", BigInt(2**63) - 1n]);
});

zeek.on('zeek_init', {priority: -20}, () => {
  // Fractional part is an error.
  try {
    zeek.event('want_int', ["XXX", 42.5]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // This doesn't work because (2**63 - 1) in JavaScript is 2**63 which
  // ends up being negative after casting.
  try {
    zeek.event('want_int', ["XXX", (2**63) - 1]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  try {
    zeek.event('want_int', ["XXX", (2**64) - 1]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  try {
    zeek.event('want_int', ["XXX", -(2**64)]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // Infinity
  try {
    zeek.event('want_int', ["XXX", Infinity]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // NaN
  try {
    zeek.event('want_int', ["XXX", NaN]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }
});


// JS number and bigint to count
zeek.on('zeek_init', {priority: -30}, () => {

  zeek.event('want_count', ["0", 0]);
  zeek.event('want_count', ["42", 42]);
  zeek.event('want_count', ["42", 42n]);

  zeek.event('want_count', ["9007199254740991", (2**53) - 1]);

  // This is a bit strange. 2**63 prints as 9223372036854776000, but then
  // you can convert it to a BigInt with more precision:
  //
  //   > x = 2**63
  //   9223372036854776000
  //   > BigInt(x)
  //   9223372036854775808n
  //
  // That is likely something V8 specific and might be confusing, but
  // for now accept it.
  zeek.event('want_count', ["9223372036854775808", 2**63]);

  // Actually test the 2**64 -1 as BigInt.
  zeek.event('want_count', ["18446744073709551615", BigInt(2**64) - 1n]);
  zeek.event('want_count', ["18446744073709551615", 18446744073709551615n]);
});

zeek.on('zeek_init', {priority: -40}, () => {
  try {
    zeek.event('want_count', ["XXX", -1]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  try {
    zeek.event('want_count', ["XXX", -(2**53 - 1)]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // Fractional part is an error.
  try {
    zeek.event('want_count', ["XXX", 42.5]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // 2**64 is too large a number for zeek_uint_t
  try {
    zeek.event('want_count', ["XXX", 18446744073709551616]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // Also a bigint of 2**64 is too large a number for zeek_uint_t
  try {
    zeek.event('want_count', ["XXX", 18446744073709551616n]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // Same as above, but written as 2**64
  try {
    zeek.event('want_count', ["XXX", BigInt(2**64)]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // Infinity
  try {
    zeek.event('want_count', ["XXX", Infinity]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }

  // NaN
  try {
    zeek.event('want_count', ["XXX", NaN]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }
});

// JS number to double tests.
zeek.on('zeek_init', {priority: -50}, () => {

  zeek.event('want_double', ["nan", NaN]);
  zeek.event('want_double', ["inf", Infinity]);
  zeek.event('want_double', ["42.0", 42.0]);
  zeek.event('want_double', ["-9.007199254740991e+15", -((2**53) - 1)]);
  zeek.event('want_double', ["9.007199254740991e+15", 2**53 - 1]);
  zeek.event('want_double', ["-1.4757395258967641e+20", -(2**67)]);
  zeek.event('want_double', ["1.4757395258967641e+20", 2**67]);
});

zeek.on('zeek_init', {priority: -60}, () => {
  // BigInt to double needs to be explicit. Sorry.
  try {
    zeek.event('want_double', ["XXX", 42n]);
  } catch (error) {
    zeek.print(`expected error: ${error}`)
  }
});

# @TEST-END-FILE

# @TEST-START-FILE consume-events.zeek

# Receives the string and int version of the value.
event want_int(sx: string, x: int) &is_used {
  print "want_int", sx, x;
  if ( sx != cat(x) )
      print fmt("ERROR wanted %s, have %s", sx, cat(x));
}

event want_count(sx: string, x: count) &is_used {
  print "want_count", sx, x;
  if ( sx != cat(x) )
      print fmt("ERROR wanted %s, have %s", sx, cat(x));
}

event want_double(sx: string, x: double) &is_used {
  print fmt("want_double %s %.3f", sx, x);
  if ( sx != cat(x) )
      print fmt("ERROR wanted %s, have %s", sx, cat(x));
}
# @TEST-END-FILE
