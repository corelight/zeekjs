# @TEST-DOC: A property with a null value is recognized for an optional field as allowed.
# @TEST-EXEC: zeek ./record.zeek ./record.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE record.js
zeek.on('zeek_init', () => {
  zeek.invoke('Call::me', [{a: 1}]);
  zeek.invoke('Call::me', [{a: 1, b: "abc", c: "127.0.0.1"}]);
  zeek.invoke('Call::me', [{a: 1, b: "cba", c: null}]);
  zeek.invoke('Call::me', [{a: 1, b: null, c: "127.0.0.2"}]);
  zeek.invoke('Call::me', [{a: 1, b: null, c: null}]);
});
@TEST-END-FILE


@TEST-START-FILE record.zeek
module Call;

export {
  type MyRecord: record {
    a: count;
    b: string &optional;
    c: addr &optional;
  };

  global me: function(r: MyRecord);
}

function me(r: MyRecord) &is_used {
  print fmt("%s", r);
}

@TEST-END-FILE
