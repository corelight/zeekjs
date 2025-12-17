# @TEST-DOC: Call a JavaScript event from a scheduled event. Regression test related to zeek/zeek#5106. See scheduled-hook-loop.sh, too.
#
# @TEST-EXEC: zeek ./test.zeek
# @TEST-EXEC: btest-diff .stdout
@TEST-START-FILE ./test.js
var last = "";
zeek.on('Test::ej', (s0, s1, c) => {
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

# ej - event javascript
global ej: event(s0: string, s1: string, c: count);

global c = 0;

event Test::e() {
    ++c;
    if ( c < 50000 )
        schedule 0.1usec { Test::e() };
    else
        terminate();

    event ej(cat("test"), cat(c), c);
}

event zeek_init() {
    event Test::e();
}

@load ./test.js
@TEST-END-FILE
