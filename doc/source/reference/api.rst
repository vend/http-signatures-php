API Reference
=============

.. contents:: Table of Contents
   :depth: 2
   :local:

.. _ref_context:

Class: Context
---------------

.. code-block:: php

  new Context($contextArgs)

The Context class is the base of all signing and verification actions.

$contextArgs is an associative array of parameters for the context. The
following keys are recognised:

.. list-table::
  :widths: 10 10 80
  :header-rows: 1

  * - Key Name
    - Type
    - Description
  * - ``keys``
    - Array of keys
    - An array of shared secret, public or private key objects
  * - ``algorithm``
    - blah
    - blah
  * - ``headers``
    - blah
    - blah

..
  'keys' => ['mykey' => file_get_contents('/path/to/privatekeyfile')],
  'algorithm' => 'rsa-sha256',
  'headers' => ['(request-target)', 'Date'],
