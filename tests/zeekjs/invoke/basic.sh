# @TEST-DOC: Tests for zeek.invoke
# @TEST-EXEC: zeek ./invoke.zeek ./invoke.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE ./invoke.js
// Interpret BigInt as simple number - do not use this unless
// you're okay loosing precision.
BigInt.prototype.toJSON = function() {
  return parseInt(this);
}


zeek.on('zeek_init', () => {
  console.log(`sqrt(9) -> ${zeek.invoke('sqrt', [9])}`);
  console.log(`count_to_addr(3232235521) -> ${zeek.invoke('count_to_v4_addr', [3232235521])}`);
  console.log(`to_port("22/tcp") -> ${JSON.stringify(zeek.invoke('to_port', ["22/tcp"]))}`);

  console.log(`Invoking Test::test_void: ${typeof(zeek.invoke('Test::test_void', ['cookie']))}`);
  console.log(`Invoking Test::test_add: ${zeek.invoke('Test::test_add', [1,2])}`);
  console.log(`Invoking Test::test_record: ${JSON.stringify(zeek.invoke('Test::test_record', [{"msg": "Hello!"}]))}`)
  console.log(`Invoking Test::test_vector_of_count: ${JSON.stringify(zeek.invoke('Test::test_vector_of_count', [[1, 2, 3]]))}`)
  console.log(`Invoking Test::test_vector_of_string: ${JSON.stringify(zeek.invoke('Test::test_vector_of_string', [["a", "b"]]))}`)
});
@TEST-END-FILE

@TEST-START-FILE ./invoke.zeek
module Test;

type MyRecord: record {
  msg: string;
  reply: string &optional;
};

function test_void(s: string) {
  print(fmt("ZEEK: test_void: '%s'", s));
}

function test_add(a: count, b: count): count {
  return a + b;
}

# Not sure how safe it is to return the same reference back to Javascript,
# but seems to work...
function test_record(r: MyRecord): MyRecord {
  print(fmt("ZEEK: Got r=%s", r));
  r$reply = fmt("Returning %s", r$msg);
  return r;
}

function test_vector_of_count(v: vector of count): count {
  local sum = 0;
  print(fmt("ZEEK: test_vector_of_count: Got v=%s", v));
  for (i in v )
    sum += v[i];

  return sum;
}

function test_vector_of_string(v: vector of string): string {
  print(fmt("ZEEK: test_vector_of_count: Got v=%s", v));
  return join_string_vec(v, "");
}
@TEST-END-FILE
