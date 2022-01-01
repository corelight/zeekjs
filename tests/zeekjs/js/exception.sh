# @TEST-DOC: Test raising exception in Javascript
# @TEST-EXEC: zeek ./exc.js ZeekJS::exit_on_uncaught_exceptions=F 2>&1
# @TEST-EXEC: grep Uncaught .stdout > uncaught
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff uncaught

@TEST-START-FILE exc.js
function c() { throw "Exception in c()"; }
function b() { c(); }
function a() { b(); }

function my_zeek_init() {
  throw "Exception in my_zeek_init()";
}

zeek.on('zeek_init', my_zeek_init);
zeek.on('zeek_init', () => { throw "Anonymous"; })

zeek.on('zeek_done', () => {
  a();
});
@TEST-END-FILE
