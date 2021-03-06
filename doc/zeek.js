/**
 * Zeek module provided by the ``zeek`` process.
 *
 * @module zeek
 */

/**
 * Register a function as a Zeek event handler.
 *
 * @param {string} name - The Zeek event name. For example, ``zeek_init``.
 * @param {object} [options] - Optional options. Only supported key is priority.
 * @param {function} handler - The function to call.
 *
 */
exports.on = function() { }

/**
 * Register a function to be called as a Zeek hook handler.
 *
 * When ``handler`` returns ``false``, this is equivalent to using ``break``
 * in a Zeek hook handler.
 *
 * @param {string} name - The name of the hook. For example, ``DNS::log_policy``.
 * @param {object} [options] - Optional options. Only supported key is priority.
 * @param {function} handler - The function to call.
 *
 */
exports.hook = function() { }

/**
 * Invoke a Zeek function.
 *
 * It is currently not possible to invoke Zeek functions or bifs that
 * take arguments of type ``any``. ZeekJS converts Javascript types to
 * concrete Zeek types. This is not possible with type ``any``.
 *
 * @param {string} name The name of the Zeek function to invoke.
 * @param {array} [args] Arguments to use.
 *
 */
exports.invoke = function() { }

/**
 * Queue a Zeek event.
 *
 * @param {string} name The name of the Zeek event to queue.
 * @param {array} [args] Arguments to use.
 *
 */
exports.event = function() { }

/**
 * Print via stdout.
 *
 * In the future this may use Zeek's ``PrintStmt`` rather than ``printf()``.
 * You should generally prefer ``console.log()``.
 *
 * @param {string} message - The message to print.
 *
 */
exports.print = function() { }

/**
 * Access Zeek side global variables.
 *
 * This object allows access to global and exported variables.
 *
 * For example::
 *
 *     zeek.global_vars["Cluster::node"]
 *     worker-01
 */
exports.global_vars = {}

/**
 * Select properties with a given attribute.
 *
 * To select only ``&log`` attributes for ``JSON.stringify()``::
 *
 *     zeek.on('HTTP::log_http' (rec) => {
 *       console.log(JSON.stringify(zeek.select_fields(rec, zeek.ATTR_LOG)));
 *     });
 *
 * @param {object} rec - A object backed by a Zeek record.
 * @param {number} mask - The attribute mask. Only ``zeek.ATTR_LOG`` supported.
 *
 */
exports.select_fields = function() {}

/**
 * Flatten a Javascript object by concatenating keys with '.'
 * similar or close to what Zeek does.
 *
 * To imitate the http.log::
 *
 *     zeek.on('HTTP::log_http' (rec) => {
 *       console.log(JSON.stringify(zeek.flatten(zeek.select_fields(rec, zeek.ATTR_LOG))));
 *     });
 *
 * @param {object} rec - The object to flatten.
 * @param {string} [prefix] - Key prefix, optional.
 * @param {object} [res] - Result object, optional.
 *
 */
exports.flatten = function() {}
