# @TEST-DOC: Call a JavaScript hook from a scheduled event. Regression test for zeek/zeek#5106 where a race between main and executor thread was reported. This test would only fail sporadically previously, but better to have it than not.
#
# @TEST-EXEC: zeek ./test.zeek
# @TEST-EXEC: btest-diff .stdout
@TEST-START-FILE ./test.js
var last = "";
zeek.hook('Test::h', (s0, s1, c) => {
    let t = s0 + "test" + s1 + c;
    last = t;
});

zeek.on('zeek_done', () => {
    console.log(last);
});
@TEST-END-FILE

@TEST-START-FILE ./test.zeek
module Test;

redef exit_only_after_terminate=T;

global h: hook(s0: string, s1: string, c: count);

function f(s0: string, s1: string, c: count) {
    hook h(s0, s1, c);
}

global c = 0;

event Test::e() {
    ++c;
    if ( c < 50000 )
        schedule 0.1usec { Test::e() };
    else
        terminate();

    f(cat("test"), cat(c), c);
}

event zeek_init() {
    event Test::e();
}

@load ./test.js
@TEST-END-FILE
