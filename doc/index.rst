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

Currently ZeekJS is compatible with Zeek 4.0, 4.1 and the latest
4.2 development version. Development happens primarily against the
latest feature release.


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
    $ cd nodejs
    $ git reset --hard v16.13.1
    $ ./configure --prefix=/opt/node-16 --shared
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

    $ ./configure --with-nodejs/opt/node-16
    $ make
    $ sudo make install

If everything worked out the plugin should be available available::

   $ zeek -NN Corelight::ZeekJS
   Corelight::ZeekJS - Experimental JavaScript support for Zeek (dynamic, version 0.1.0)
       Implements LoadFile (priority 0)
       Implements DrainEvents (priority 0)


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

* It is not possible to call Zeek functions with arguments of type ``any``.
  ZeekJS converts arguments into the types Zeek functions declare. This trick
  doesn't work for ``any``. You can work around this by adding typed trampoline
  functions in Zeek script.

* No setter-access on Zeek objects. It's not possible to modify fields of Zeek
  records from JavaScript. The ``Setter()`` logic isn't (yet) implemented.

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
    {"ts":1630238733.951343,"uid":"CTnlMb4FxnHW2obuR3","id":{"orig_h":"172.20.10.3","orig_p":55767,"resp_h":"172.20.10.1","resp_p":53},"proto":"udp","trans_id":"43556","rtt":0.03791093826293945,"query":"corelight.com","qclass":"1","qclass_name":"C_INTERNET","qtype":"1","qtype_name":"A","rcode":"0","rcode_name":"NOERROR","AA":false,"TC":false,"RD":true,"RA":true,"Z":"0","answers":["199.60.103.106","199.60.103.6"],"TTLs":[77,77],"rejected":false,"total_answers":"2","total_replies":"3","saw_query":true,"saw_reply":true,"_log_id":"dns"}



API Reference
=============

The plugin adds a ``zeek`` object into the global namespace. This object
provides the following functions to interact with Zeek.

.. module:: zeek
.. autofunction:: on
.. autofunction:: hook
.. autofunction:: event
.. autofunction:: invoke
.. autoattribute:: global_vars
