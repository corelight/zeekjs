# @TEST-DOC: Invoking Reporter::info should not crash
# @TEST-EXEC: zeek ./reporter.js
# @TEST-EXEC: zeek-cut level message location < reporter.log > reporter.log.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff reporter.log.cut


@TEST-START-FILE reporter.js
zeek.on('zeek_init', () => {
  zeek.invoke('Reporter::info', ['An info message via Reporter::info']);
  zeek.invoke('Reporter::warning', ['A warning message via Reporter::warning']);
  // do not call error in zeek_init(), it makes Zeek fail...
  // zeek.invoke('Reporter::error', ['An warning message via Reporter::error']);
});
@TEST-END-FILE
