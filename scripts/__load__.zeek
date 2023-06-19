# JavaScript settings

module JavaScript;

export {
	## The Javascript code executed for bootstrapping.
	## This comes fairly straight from the embedding guide to support using
	## require() with filesystem paths in the process working directory.
	##
	## https://docs.w3cub.com/node~14_lts/embedding
	##
	const main_script_source: string = cat(
		"const module_mod = require('module')\n",
		"const publicRequire = module_mod.createRequire(process.cwd() + '/');\n",
		"globalThis.require = publicRequire;\n",
		"\n",
		"globalThis.zeek_javascript_init = async () => {\n",
		"  const zeek = process._linkedBinding('zeekjs').zeek;\n",
		"  // Helper for zeek record rendering.\n",
		"  zeek.flatten = (obj, prefix, res) => {\n",
		"    res = res || {}\n",
		"    for (const k in obj) {\n",
		"      const nk = prefix ? `${prefix}.${k}` : k\n",
		"      const v = obj[k]\n",
		"\n",
		"      // Recurse for objects, unless it's actually an array, or has a\n",
		"      // custom toJSON() method (which is true for the port objects).\n",
		"      if (v !== null && typeof(v) == 'object' && !Array.isArray(v) && !('toJSON' in v)) {\n",
		"        zeek.flatten(v, nk, res)\n",
		"      } else {\n",
		"        res[nk] = v\n",
		"      }\n",
		"    }\n",
		"    return res\n",
		"  }\n",
		"\n",
		"  const m = new module_mod();\n",
		"  // Compile a new module that imports all .js files found using import().\n",
		"  //\n",
		"  // https://stackoverflow.com/a/17585470/9044112\n",
		"  return m._compile('const ps = []; zeek.__zeek_javascript_files.forEach((fn) => { ps.push(import(fn)); }); return Promise.all(ps);', process.cwd() + '/');\n",
		"};\n",
		"// Add a global zeek object from the linked zeekjs binding\n",
		"globalThis.zeek = process._linkedBinding('zeekjs').zeek;\n"
	) &redef;

	## Vector of filenames to compile/execute after the bootstrap file.
	const files: vector of string = {} &redef;

	## Be very conservative.
	const initial_heap_size_in_bytes: count = 64 * 1024 * 1024 &redef;
	const maximum_heap_size_in_bytes: count = 128 * 1024 * 1024 &redef;
	const thread_pool_size: count = 4 &redef;

	## Node.js default behavior is to exit a process on uncaught exceptions.
	## Specifically exceptions in timer callbacks are problematic as a throwing
	## timer callback may break subsequently scheduled timers.
	##
	## Set this to F in order to just keep going when errors happen. Note,
	## if you see any Uncaught errors, this likely means the Javascript
	## state is corrupt.
	const exit_on_uncaught_exceptions: bool = T &redef;
}
