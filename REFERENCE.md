Reference Implementation
=========================

This library includes a reference client and server to demonstrate compliance
with the v10 Reference Tests, as well as providing a utility for generating
headers from the commandline.

# Client & Server

The ``/reference`` directory contains artefacts such as keys and the reference
HTTP message, as well as scrips and PHP files to run the reference client
and server.

## Preparation

The project needs to be checked out and locally configured to run the
reference client & server. Specifically the "dev" dependencies are not
installed when simply included in a library.

The command ``composer`` is presumed to be included in your path.

```sh
git clone https://github.com/liamdennehy/http-signatures-php.git
cd http-signatures-php
git checkout -b reference ff630c855a4e237600852baf32f9ea3da9843409
```

## Server

To start the server, run the ``server.sh`` script in a dedicated window (note
this command will remain active until terminated with ``CTRL + C``, so MUST
be run in a separate shell instance):

```sh
clear && /bin/sh ./reference/server.sh
```

## Client

Once the server is running (check the console running the server command),
run the ``client.sh`` script in a separate window form the server instance:

```sh
clear && /bin/sh ./reference/client.sh
```

# Header Generator

TODO: Implement a header generator for a custom input http message & key