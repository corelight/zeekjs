.. ZeekJS documentation master file, created by
   sphinx-quickstart on Sat Dec 18 13:25:25 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

ZeekJS
======

ZeekJS is an experimental `Zeek <https://zeek.org>`_ plugin to support
JavaScript as an alternative scripting language in Zeek.

.. code-block:: javascript

    zeek.on('zeek_init', function() {
      console.log('Hello, Zeek!');
    });


The plugin embeds `Node.js <https://nodejs.org>`_ and primarily deals with
converting between JavaScript and Zeek data types and registering JavaScript
functions as event or hook handlers within Zeek. It further installs Node's IO
loop as an IO source in Zeek.

Getting started
===============

Compiling and running ZeekJS requires a Zeek installation and Node.js
available as a shared library.

Zeek
----

Currently ZeekJS strives to be compatible with latest stable, feature and
nightly releases of Zeek.

.. note::

   With Zeek version 6.0, the ZeekJS plugin is automatically included as
   a builtin plugin when Node.js is available on the build system.
   The Zeek documentation received a section about
   `JavaScript <https://docs.zeek.org/en/master/scripting/javascript.html>`_,
   too.


Node.js
-------

If your operating system offers a way to install a modern Node.js version
as a shared library and includes development headers as well, that makes
things easy. For example, on Fedora 34 and 35 all that is needed is to
install the ``nodejs-devel`` and ``nodejs-lib`` packages.

If you're not using Fedora, you'll probably need to compile Node.js yourself.


Compiling Node.js from source
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Start by fetching a `source tarball <https://nodejs.org/en/download/>`_,
or cloning the `Node.js repository <https://github.com/nodejs/node>`_ and
check out the tag of the release you want to build. Then, configure, compile
and install it.

.. code::

    $ git clone https://github.com/nodejs/node.git
    $ cd node
    $ git reset --hard v19.9.0
    $ ./configure --prefix=/opt/node-19 --shared
    $ make
    $ sudo make install


With Node.js in place, you should be prepared to compile ZeekJS.


You may want to look into ``docker/debian.Dockerfile`` for some inspiration
around installing Node.js on Debian or other distributions.


Compiling ZeekJS
----------------

ZeekJS is a standard Zeek plugin. Existing documentation around building
and installing Zeek plugins should apply to it as well.
Ensure that ``zeek-config`` is in your path, then use ``./configure`` and
``make`` for building and installing.

If Node.js is installed in a non-standard location, use
``--with-nodejs=/path/to/nodejs``.

For example::

    $ zeek-config --version
    4.1.1

    $ ./configure --with-nodejs=/opt/node-19
    $ make
    $ sudo make install

If everything worked out the plugin should be available available::

   $ zeek -NN Zeek::JavaScript
   Zeek::JavaScript - Experimental JavaScript support for Zeek (dynamic, version 0.7.0)
       Implements LoadFile (priority 0)


Hello, Zeek!
------------

Verify ZeekJS is functional by running a JavaScript file using Zeek::


    $ cat << EOF > hello.js
    zeek.on('zeek_init', function() {
      console.log('Hello, Zeek!');
    });
    EOF

    $ zeek ./hello.js
    Hello, Zeek!


Limitations
===========

* No multi-index support for tables and sets. JavaScript objects have string
  properties only.


Generally, look out for ``[ ERROR ]`` messages on ``stderr``.
If something doesn't seem to work, it may just not be implemented.

Examples
========

Exposing Zeek stats via HTTP
----------------------------

This example shows how to start a HTTP server and expose network and event
stats gathered by invoking the bifs ``get_net_stats()`` and ``get_event_stats()``.

.. literalinclude:: examples/http-stats.js
    :language: javascript

.. code::

    $ curl -sfS localhost:3000 | jq
    {
      "net": {
        "pkts_recvd": "4861",
        "pkts_dropped": "0",
        "pkts_link": "4861",
        "bytes_recvd": "6319316"
      },
      "event": {
        "queued": "431",
        "dispatched": "431"
      },
      "zeek_version": "4.1.1-debug"
    }


Taking over logging
-------------------

This leverages Zeek 4.1's new ``Log::log_stream_policy`` hook to bypass
Zeek logging.

.. literalinclude:: examples/log-bypass.js
    :language: javascript

This will write JSON log entries into ``dns.log``, ``http.log`` and ``ssl.log``
when running, for example::

    $ zeek -r tests/Traces/dns-http-https.pcap ./log-bypass.js
    $ cat dns.log
    {"ts":1630238733.951343,"uid":"CS00HK1MFHn2F03Px2","id.orig_h":"172.20.10.3","id.orig_p":55767,"id.resp_h":"172.20.10.1","id.resp_p":53,"proto":"udp","trans_id":"43556","rtt":0.03791093826293945,"query":"corelight.com","qclass":"1","qclass_name":"C_INTERNET","qtype":"1","qtype_name":"A","rcode":"0","rcode_name":"NOERROR","AA":false,"TC":false,"RD":true,"RA":true,"Z":"0","answers":["199.60.103.106","199.60.103.6"],"TTLs":[77,77],"rejected":false}



API Reference
=============

The plugin adds a ``zeek`` object into the global namespace. This object
provides the following functions to interact with Zeek.

.. module:: zeek
.. autofunction:: on
.. autofunction:: hook
.. autofunction:: event
.. autofunction:: invoke
.. autofunction:: as
.. autofunction:: select_fields
.. autofunction:: flatten
.. autoattribute:: global_vars
