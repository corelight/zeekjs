# ZeekJS

Experimental JavaScript support for Zeek.

```
$ cat hello.js
zeek.on('zeek_init', function() {
  console.log('Hello, Zeek!');
});

$ zeek ./hello.js
Hello, Zeek!
```

## Building

To build the plugin, you require Node.js as a shared library. On Fedora
you can install the packages `nodejs-devel` and `v8-devel`. On Ubuntu
(starting with Kinetic Kudo, 22.10) and Debian (testing/bookworm), installing
the `libnode-dev` package is sufficient.

On other or older Linux distributions, or MacOSX, you'll need to compile
Node.js yourself using `--shared`. See, for example, [debian.Dockerfile](./docker/debian.Dockerfile)
in the `docker` directory for inspiration.

Otherwise, ZeekJS builds and installs like a normal Zeek plugin.

Starting with version 0.4.2, it is possible to install ZeekJS via `zkg`, too:

```
zkg install zeekjs
```

## Documentation

To build online documentation for ZeekJS, change into the `docs` directory
and run `make html` if sphinx/jsdoc is available locally, or run
`make container-html` to use a Docker container.

The [API documentation](https://zeekjs.readthedocs.io/en/latest/#api-reference) is also available on Read the Docs.

The existing [tests](./tests) are a source of documentation, too, and there
are a few [examples](./examples) in the repository as well.
