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
		"const publicRequire = require('module').createRequire(process.cwd() + '/');\n",
		"globalThis.require = publicRequire;\n\n",
		"zeek.__zeekjs_files.forEach((fn) => { publicRequire(fn); })\n"
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
