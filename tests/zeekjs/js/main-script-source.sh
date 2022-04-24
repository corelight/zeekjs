# @TEST-DOC: Test overriding the main script source
# @TEST-EXEC: zeek ZeekJS::main_script_source="globalThis.zeekjs_init = () => { console.log('I know better how to bootstrap!'); zeek.__zeekjs_files.forEach((x, i) => console.log(i + ' ' + x)) };" mod1.js mod2.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE mod1.js
zeek.on('zeek_init', _ => console.log('JS: zeek_init'));

@TEST-END-FILE
@TEST-START-FILE mod2.js
zeek.on('zeek_done', _ => console.log('JS: zeek_done'));
@TEST-END-FILE
