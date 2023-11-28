# @TEST-DOC: Test handling of opaques via JavaScript
# @TEST-EXEC: zeek -B plugin-Zeek-JavaScript ./opaque.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE ./opaque.js

zeek.on('zeek_init', { priority: 2 }, () => {
  let sha256_opaque = zeek.invoke('sha256_hash_init');
  console.log('sha256_opaque', typeof(sha256_opaque), sha256_opaque);
  zeek.invoke('sha256_hash_update', [sha256_opaque, 'test\n']);
  let hash = zeek.invoke('sha256_hash_finish', [sha256_opaque]);
  console.log('sha256 hash of \'test\\n\' is', hash);
});

zeek.on('zeek_init', { priority: 1 }, () => {
  let topk_opaque = zeek.invoke('topk_init', [5]);
  console.log('topk_opaque', typeof(topk_opaque), topk_opaque);
  zeek.invoke('topk_add', [topk_opaque, zeek.as('string', 'a')]);
  zeek.invoke('topk_add', [topk_opaque, zeek.as('string', 'a')]);
  zeek.invoke('topk_add', [topk_opaque, zeek.as('string', 'b')]);
  zeek.invoke('topk_add', [topk_opaque, zeek.as('string', 'a')]);
  zeek.invoke('topk_add', [topk_opaque, zeek.as('string', 'c')]);
  zeek.invoke('topk_add', [topk_opaque, zeek.as('string', 'd')]);
  zeek.invoke('topk_add', [topk_opaque, zeek.as('string', 'e')]);
  zeek.invoke('topk_add', [topk_opaque, zeek.as('string', 'b')]);
  let tops = zeek.invoke('topk_get_top', [topk_opaque, 2]);
  console.log('tops', tops);
});

zeek.on('zeek_init', () => {
  // Making sure we do not crash accessing properties on opaque values.
  let topk_opaque = zeek.invoke('topk_init', [5]);
  console.log('topk_opaque.invalid', topk_opaque.invalid);
});
@TEST-END-FILE
