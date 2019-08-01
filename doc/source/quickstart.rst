==========
Quickstart
==========

This page provides a quick introduction to Guzzle and introductory examples.
If you have not already installed, Guzzle, head over to the :ref:`installation`
page.

.. _signing_quickstart:

Signing a message
==================

Once you have a PSR-7 message ready to send,
create a Context with:

* your chosen algorithm
* the list of headers to include in the signature
* the key you will use to sign the message

For these examples we will sign the method + URI (indicated by
``(request-target``) and the ``Content-Type`` header. This provides a very
basic level of protection, and you should consider the headers you sign
in your application carefully. These may also be specified by the verifier
(most often a server hosting an API or web service).

Note also that this does not apply only to HTTP requests sent by a client.
Servers can add a signature to responses that the client can verify.

Shared Secret Context (HMAC)
-------------------------------

This type of signature uses a secret key known to you and the verifier.

.. code-block:: php

  use HttpSignatures\Context;

  $context = new Context([
    'keys' => ['key12' => 'your-secret-here'],
    'algorithm' => 'hmac-sha256',
    'headers' => ['(request-target)', 'Content-Type'],
  ]);


Private Key Context (RSA)
---------------------------

This type of signature uses a private key known only to you, which can be
verified using a public key that is known to anyone who wants to verify the
message.

The key file is assumed to be an unencrypted private key in PEM format.

.. code-block:: php

  use HttpSignatures\Context;

  $context = new Context([
    'keys' => ['key43' => file_get_contents('/path/to/privatekeyfile')],
    'algorithm' => 'rsa-sha256',
    'headers' => ['(request-target)', 'Date', 'Accept'],
  ]);

Signing the Message:
---------------------

.. code-block:: php

  $context->signer()->sign($message);

Now `$message` contains the ``Signature`` header:

.. code-block:: php

  $message->headers->get('Signature');
  // keyId="examplekey",algorithm="hmac-sha256",headers="...",signature="..."

..  $message->headers->get('Authorization');
  // Signature keyId="examplekey",algorithm="hmac-sha256",headers="...",signature="..."

Adding a Digest header while signing
-------------------------------------

Include a ``Digest`` header automatically when signing to also protect the
payload (body) of the message in addition to the request-target and headers:

.. code-block:: php

  $context->signer()->signWithDigest($message);
  $message->headers->get('digest');
  // SHA-256=<base64SHA256Digest>


