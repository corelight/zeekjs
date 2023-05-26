/**
 * Zeek module provided by the ``zeek`` process.
 *
 * @module zeek
 */

/**
 * Register a function to be called as a Zeek event handler.
 *
 * @example
 * zeek.on('zeek_init', () => {
 *   console.log('Hello, Zeek!');
 * });
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
 * Conversion of ``args`` to Zeek function arguments happens implicitly.
 *
 * Invoking Zeek hooks is possible. If any of the hook handlers break,
 * the return value will be false, else true.
 *
 * To invoke a Zeek function taking an ``any`` typed parameter, use
 * ``zeek.as`` to convert a JavaScript value to a Zeek value and use
 * the resulting object. The plugin will thread through the underlying
 * Zeek value without attempting implicit conversion.
 *
 * @example
 * zeek.on('zeek_init', () => {
 *   let version = zeek.invoke('zeek_version');
 *   console.log(`Running on Zeek ${version}`);
 * });
 *
 *
 * @param {string} name The name of the Zeek function to invoke.
 * @param {array} [args] Arguments to use.
 *
 */
exports.invoke = function() { }

/**
 * Explicit type conversion from JavaScript to Zeek.
 *
 * @param {string} type_name The name of the Zeek type. For example, ``addr``.
 * @param {} [value] The value to convert to ``type_name``.
 *
 * @returns An object referencing a Zeek value of type ``type_name``.
 */
exports.as = function() { }


/**
 * Queue a Zeek event.
 *
 * Conversion of ``args`` to Zeek event arguments happens implicitly.
 *
 * @param {string} name The name of the Zeek event to queue.
 * @param {array} [args] Arguments to use.
 *
 */
exports.event = function() { }

/**
 * Access Zeek side global variables.
 *
 * This object allows access to global and exported variables.
 *
 * @example
 * zeek.global_vars["Cluster::node"]
 * worker-01
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
 * @param {number} mask - The attribute mask. Only ``zeek.ATTR_LOG`` is currently supported.
 *
 */
exports.select_fields = function() {}

/**
 * Flatten a Javascript object by concatenating nested properties with `.`
 * similar to how Zeek would log them in JSON format.
 *
 * @example
 * // http.log imitation
 * zeek.on('HTTP::log_http' (rec) => {
 *   let log_rec = zeek.select_fields(rec, zeek.ATTR_LOG);
 *   console.log(JSON.stringify(zeek.flatten(log_rec)));
 * });
 *
 * @param {object} rec - The object to flatten.
 * @param {string} [prefix] - Key prefix, optional.
 * @param {object} [res] - Result object, optional.
 *
 */
exports.flatten = function() {}
