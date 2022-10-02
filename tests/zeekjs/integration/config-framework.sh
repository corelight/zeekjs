
# @TEST-DOC: Javascript calling Config::set_value()
# @TEST-EXEC: zeek ./config.js ./config.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE config.js
zeek.on('zeek_init', () => {

  zeek.print('JS: changing my_count');
  zeek.invoke('Config::set_value', ['Test::my_count', zeek.as('count', 4242)]);

  zeek.print('JS: changing my_addr');
  // Sketching out the generic approach getting the type_name
  // from global_ids().
  let global_ids = zeek.invoke('global_ids');
  let option = 'Test::my_addr';
  let type_str = global_ids[option].type_name;
  let as_obj = zeek.as(type_str, '11.22.33.44');
  zeek.invoke('Config::set_value', [option, as_obj]);

  zeek.invoke('Config::set_value', ['Test::my_vec', zeek.as('count_vec', [4,5,6])]);
});
@TEST-END-FILE

@TEST-START-FILE config.zeek
@load base/frameworks/config
export {
  type count_vec: vector of count;
}

module Test;
export {
  option my_count: count = 42;
  option my_addr: addr = 1.2.3.4;
  option my_vec: count_vec = vector(1, 2, 3);
}

function change_count(ID: string, new_value: count): count {
  print fmt("ZEEK: change_count: %s changed from %s to %s", ID, my_count, new_value);
  return new_value;
}

function change_addr(ID: string, new_value: addr): addr {
  print fmt("ZEEK: change_addr: %s changed from %s to %s", ID, my_count, new_value);
  return new_value;
}

function change_count_vec(ID: string, new_value: count_vec): count_vec{
  print fmt("ZEEK: change_count_vec: %s changed from %s to %s", ID, my_vec, new_value);
  return new_value;
}

event zeek_init() &priority=100 {
  print fmt("ZEEK: zeek_init: my_count=%s", my_count);
  print fmt("ZEEK: zeek_init: my_addr=%s", my_addr);
  print fmt("ZEEK: zeek_init: my_vec=%s", my_vec);
  Option::set_change_handler("Test::my_count", change_count);
  Option::set_change_handler("Test::my_addr", change_addr);
  Option::set_change_handler("Test::my_vec", change_count_vec);
}

event zeek_done() {
  print fmt("ZEEK: zeek_done: my_count=%s", my_count);
  print fmt("ZEEK: zeek_done: my_addr=%s", my_addr);
  print fmt("ZEEK: zeek_done: my_vec=%s", my_vec);
}
@TEST-END-FILE
