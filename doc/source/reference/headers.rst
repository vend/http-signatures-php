=========================
The HTTP Signature
=========================

This section is based on the definitions and descriptions in
`Signing HTTP Messages IETF draft RFC version 10
<https://tools.ietf.org/html/draft-cavage-http-signatures-10>`_.

.. contents:: Table of Contents
   :depth: 1
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

.. _signature_line_keyid:

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

.. _signature_line_algorithm:

algorithm
----------

The ``algorithm`` parameter informs the verifier which hash algorithm was used
to generate the hash signed by the signature ("hash" algorithm),
and which cryptographic algorithm was used to sign that resulting hash
("signature algorithm").

The hash algorithm cannot be deduced simply by looking at the key and
signature, so must be provided in this parameter.

However the verifier should not rely on the signature algorithm part
of the ``algorithm`` parameter alone to determine which signature algorithm to use.
Rather the "metadata" (e.g. which elliptic curve algorithm the key
is designed for) associated with the key should be relied on separate
from the signed message.

This arises as some types of keys can be used in multiple modes, and
selecting the wrong mode for verification may introduce security issues.

In any case the signer and verifier should agree which hash and signature
algorithms are acceptable for a given request/response.

.. _signature_line_headers:

headers
--------

The ``headers`` parameter is a space-delimited list of the headers that are
included in the signature itself. These headers are specified in lowercase,
and let the verifier know which order to place the headers in when the
signature is verified - so this order cannot be altered.

The signer and verifier(s) need to agree on which headers should be included
in any signature, especially if there are minimum headers that must be included
and any that are forbidden.

If this parameter is missing from a provided signature line, then the default
value "``date``" is used to verify the signature.

.. _signature_line_signature:

signature
----------

The ``signature`` parameter is simply a base64-encoded string representing
the raw digital signature (which is likely encoded with unprintable characters).

The verifier can use this string, along with the other parameters and headers
in the HTTP message, to verify the contents of the message (specifically the
message's :ref:`signature_line_headers`) have not been altered since the signer
generated the signature.

Headers
==========

.. _header-authorization:

Authorization header
--------------------

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
message, and is not useful in a HTTP Response.

.. _header-signature:

Signature header
----------------

.. code-block:: text

  Signature: <signatureline>

The ``Signature`` header is a new HTTP header proposed in
`<https://tools.ietf.org/html/draft-cavage-http-signatures>`_.

The value of the header is simply the :ref:`header-signatureline`.

This header is more versatile than the ``Authorization`` header as it can
be used:

- by both the client *and* server (HTTP request and HTTP respnse respectively)
- to prove the identity of the signer (similar to the ``Authorization`` header
  in ``Signature`` mode
- in addition to an ``Authorization`` header when needed

Digest header
-------------

.. code-block:: text

  Digest: SHA-256=<base64string>

The ``Digest`` header is a base64-encoded representation of the hash of
the message payload (aka body). It is defined in :rfc:`3230`. Note that this
library has only rudimentary support for this specification e.g. can only
include a single digest value while the RFC requires support for multiple
digests.

Including the ``Digest`` header in the
signature's
:ref:`signature_line_signature` allows the integrity of the payload to be
included in the signature itself.

When the message has no payload - e.g. a GET request, or a reponse with code
`202` - the digest is calculated on the empty string ``''``.
