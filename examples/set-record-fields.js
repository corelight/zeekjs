zeek.hook('Test::policy', function(rec) {
  console.log('JS: Modifying rec.s');
  rec.s = rec.s + ' from JS';
});
