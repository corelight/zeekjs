# @TEST-DOC: Can we access cluster variables and stop using terminate()?
# @TEST-EXEC: CLUSTER_NODE=worker-01 zeek 'exit_only_after_terminate=T' ./cluster.js
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE cluster.js
zeek.on('zeek_init', function() {
  console.log(`Hey, I am ${zeek.global_vars['Cluster::node']}`);
  console.log(`Cluster::nodes=${JSON.stringify(zeek.global_vars['Cluster::nodes'])}`);
});
zeek.on('zeek_init', { priority: -10 }, function() {
  zeek.invoke('terminate');
});
@TEST-END-FILE

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
  ["worker-01"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
};

@TEST-END-FILE
