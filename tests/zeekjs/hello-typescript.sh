# @TEST-EXEC: zeek ./hello.ts
# @TEST-EXEC: btest-diff .stdout
# @TEST-GROUP: smoke

@TEST-START-FILE hello.ts
function hello_from(from: string): string {
  return `Hello from ${from}!`;
}

zeek.on('zeek_init', function() {
  let text = hello_from('Typescript');
  zeek.print(text);
});

@TEST-END-FILE
