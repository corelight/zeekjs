# ZeekJS settings

module ZeekJS;

export {
	## The Javascript code executed for bootstrapping.
	## This comes fairly straight from the embedding guide to support using
	## require() with filesystem paths in the process working directory.
	##
	## https://docs.w3cub.com/node~14_lts/embedding
	##
	const main_script_source: string = cat(
		"const module = require('module')\n",
		"const publicRequire = module.createRequire(process.cwd() + '/');\n",
		"globalThis.require = publicRequire;\n\n",
		"globalThis.zeekjs_init = async () => {\n",
		"  const m = new module();\n",
		"  // Compile a new module that imports all .js files found using import().\n",
		"  //\n",
		"  // https://stackoverflow.com/a/17585470/9044112\n",
		"  return m._compile('const ps = []; zeek.__zeekjs_files.forEach((fn) => { ps.push(import(fn)); }); return Promise.all(ps);', process.cwd() + '/');\n",
		"};\n\n"
	) &redef;

	## Vector of filenames to compile/execute after the bootstrap file.
	option files: vector of string = {} &redef;

	## Be very conservative.
	option initial_heap_size_in_bytes: count = 64 * 1024 * 1024;
	option maximum_heap_size_in_bytes: count = 128 * 1024 * 1024;
	option thread_pool_size: count = 4;

	## Node.js default behavior is to exit a process on uncaught exceptions.
	## Specifically exceptions in timer callbacks are problematic as a throwing
	## timer callback may break subsequently scheduled timers.
	##
	## Set this to F in order to just keep going when errors happen. Note,
	## if you see any Uncaught errors, this likely means the Javascript
	## state is corrupt.
	option exit_on_uncaught_exceptions: bool = T;
}
