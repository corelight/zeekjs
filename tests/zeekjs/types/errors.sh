# @TEST-DOC: Test some error cases converting Javascript into Zeek types
# @TEST-EXEC: zeek ./emitter.js receiver.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE emitter.js

zeek.on('zeek_init', () => {
  zeek.print('Unknown event');
  try {
    zeek.event('EventReceiver::unknown');
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('Not enough arguments');
  try {
    zeek.event('EventReceiver::event1', []);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('Too many arguments');
  try {
    zeek.event('EventReceiver::event1', [1, 2, 3]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('Missing ts key in object');
  try {
    zeek.event('EventReceiver::event1', [{'wrong': 1234}]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('Null ts value in object');
  try {
    zeek.event('EventReceiver::event1', [{'ts': null}]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('ts can not be converted to timestamp');
  try {
    zeek.event('EventReceiver::event1', [{'ts': 'not a timestamp'}]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('can not convert to count');
  try {
    zeek.event('EventReceiver::event2', ['scramble']);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('pass an object instead of an array');
  try {
    zeek.event('EventReceiver::event3', [{'x': 1}]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('pass a string instead of an array');
  try {
    zeek.event('EventReceiver::event3', ['scramble']);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('pass a string inside an array instead of a count');
  try {
    zeek.event('EventReceiver::event3', [['scramble']]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('pass an object inside an array instead of a count');
  try {
    zeek.event('EventReceiver::event3', [[{scramble: 'scramble'}]]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

  zeek.print('pass an object as second element inside an array instead of a count');
  try {
    zeek.event('EventReceiver::event3', [[1, {scramble: 'scramble'}]]);
  } catch (error) {
    zeek.print(`Caught it: ${error}`)
  }

});
@TEST-END-FILE


@TEST-START-FILE receiver.zeek
module EventReceiver;

export {

  type MyRecord: record {
    ts: time;
  };

  global event1: event(r: MyRecord);
  global event2: event(c: count);
  global event3: event(v: vector of count);
}

event EventReceiver::event1(r: MyRecord) {
  print(fmt("[ZEEK] event1 received r=%s", r));
}

event EventReceiver::event2(c: count) {
  print(fmt("[ZEEK] event2 received c=%s", c));
}

event EventReceiver::event3(v: vector of count) {
  print(fmt("[ZEEK] event3 received v=%s", v));
}

@TEST-END-FILE
