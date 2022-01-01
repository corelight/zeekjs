# ZeekJS

Experimental JavaScript support for Zeek.

```
$ cat hello.js
zeek.on('zeek_init', () => {
  console.log('Hello, Zeek!');
});

$ zeek ./hello.js
Hello, Zeek!
```

## Building

To build the plugin, you require Node.js as a shared library. On Fedora
you can install the packages `nodejs-devel` and `v8-devel`. On Debian or
MacOSX you'll need to compile Node.js yourself.

See, for example, [debian.Dockerfile](./docker/debian.Dockerfile) in the `docker`
directory for inspiration.

Otherwise, ZeekJS builds like a normal Zeek plugin.

## Documentation

To build online documentation for ZeekJS, change into the `docs` directory
and run `make html` if sphinx/jsdoc is available locally, or
`make container-html` to use Docker for building documentation.

The existing [tests](./tests) are a good source of documentation and there
are a few [examples](./examples), too.
