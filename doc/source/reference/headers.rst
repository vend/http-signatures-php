=========================
The HTTP Signature
=========================

This section is based on the Signing HTTP Messages IETF draft RFC version 10:

https://tools.ietf.org/html/draft-cavage-http-signatures-10

.. contents:: Table of Contents
   :depth: 2
   :local:

.. _header-signatureline:

Signature Line
===============

.. code-block:: text

  keyId="abc123",algorithm="rsa-sha256",headers="(request-target) date",signature="base64string"

The Signature line is the component of a signature header that describes the
parameters of how a message was signed as well as the actual digital signature.

These parameters together should provide any verifier with the information
required to prove the validity of a signature against the HTTP message it
accompanies.

The parameters of the Signature Line are described here

keyId
------

As desribed in the `draft RFC <https://tools.ietf.org/html/draft-cavage-http-signatures-10#section-2.1.4>`_,
the ``keyId`` parameter is used by the verifier to look up the key that can
be used to verify the provided signature.

- In the HMAC case these are the same key - the shared secret.
- In the RSA or EC case, this is the public component of the key.

Note that the RFC is not specific about the meaning of the parameter's value.
This could be a fingerprint of the certificate containing the key, the
e-mail address of the signer, or even no value at all if the verifier can
determine which key to use by another means entirely e.g. if the key/certificate
is provided in a dedicated header.

The value of ``keyId`` must therefore be agreed before the message is
transmitted - either by agreeing an explicit value, or the format of the
value acceptable to the verifier if it not distinct.
This is typically found in the API documentation for the resource.

algorithm
----------

headers
--------

signature
----------


Headers
==========

.. _header-authorization:

Authorization header
----------------------

.. code-block:: text

  Authorization: Signature <signatureline>

The ``Authorization`` header is described in
:rfc:`7235#section-4.2` and provides
a way for a HTTP client to "authenticate itself with an origin server". This
gives a hint that the header is used almost exclusively by a client
when talking to a server.

The first parameter of an ``Authorization`` header is the authorization type,
of which many have been defined. When the type is ``Signature``, the server
will expect the next parameters to be a :ref:`header-signatureline` according
to the specifications of
`<https://tools.ietf.org/html/draft-cavage-http-signatures>`_

Since this header is involved primarily with authenticating a client to a
server, this header is not typically used to protect the content of a
message.

.. _header-signature:

Signature header
----------------

.. code-block:: text

  Signature: <signatureline>

The ``Signature`` header is a new HTTP header proposed in
`<https://tools.ietf.org/html/draft-cavage-http-signatures>`_.

The value of the header is simply the ref:`header-signatureline`.

This header is more versatile than the ``Authorization`` header as it can
be used:

- by both the client *and* server (HTTP request and HTTP respnse respectively)
- to prove the identity of the signer (similar to the ``Authorization`` header
  in ``Signature`` mode
- in addition to an ``Authorization`` header when needed

