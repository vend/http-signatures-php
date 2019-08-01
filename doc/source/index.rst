.. http-signatures-php documentation master file, created by
   sphinx-quickstart on Wed Jul 31 15:41:36 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. Welcome to http-signatures-php's documentation!
   ===============================================

HTTP Signatures PHP library
============================

PHP implementation of `Signing HTTP Messages
<https://tools.ietf.org/html/draft-cavage-http-signatures-10>`_ draft IETF specification,
allowing cryptographic signing and verifying of 
`PHP PSR-7 messages <http://www.php-fig.org/psr/psr-7/>`_.


.. Indices and tables
  ==================

    * :ref:`genindex`
    * :ref:`modindex`
    * :ref:`search`

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   overview
   quickstart


Usage
------

Add `liamdennehy/http-signatures <https://packagist.org/packages/liamdennehy/http-signatures>`_
to your ``composer.json``. Full instructions can be found in :ref:`installation`

To quickly see how a message is signed, take a look in :ref:`signing_quickstart`
in the Quickstart guide.


Verifying a Signed Message
````````````````````````````

Most parameters are derived from the Signature in the signed message, so the
Context can be created with fewer parameters.

It is probably most useful to create a Context with multilpe keys/certificates.
the signature verifier will look up the key using the keyId attribute of the
Signature header and use that to validate the signature.

Verifying a HMAC signed message
'''''''''''''''''''''''''''''''''

A message signed with an hmac signature is verified using the same key as
the one used to sign the original message:

.. code-block:: php

  use HttpSignatures\Context;

  $context = new Context([
    'keys' => ['key300' => 'some-other-secret',
                'key12' => 'secret-here']
  ]);

  $context->verifier()->isSigned($message); // true or false


Verifying a RSA signed message
'''''''''''''''''''''''''''''''''

An RSA signature is verified using the certificate associated with the
Private Key that created the message. Create a context by importing
the X.509 PEM format certificates in place of the 'secret':

.. code-block:: php

  use HttpSignatures\Context;

  $context = new Context([
    'keys' => ['key43' => file_get_contents('/path/to/certificate'),
               'key87' => $someOtherCertificate],
  $context->verifier()->isSigned($message); // true or false
  ]);


Verifying a message digest
''''''''''''''''''''''''''''

To confirm the body has a valid digest header and the header is a valid digest
of the message body:

.. code-block:: php

  $context->verifier()->isValidDigest($message); // true or false


An all-in-one validation that the signature includes the digest, and the digest
is valid for the message body:


.. code-block:: php

  $context->verifier()->isSignedWithDigest($message); // true or false


### Symfony compatibility

Symfony requests normalize query strings which means the resulting request target can be incorrect. See https://github.com/symfony/psr-http-message-bridge/pull/30

When creating PSR-7 requests you use `withRequestTarget` to ensure the request target is correct. For example

.. code-block:: php

  use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
  use Symfony\Component\HttpFoundation\Request;

  $symfonyRequest = Request::create('/foo?b=1&a=2');
  $psrRequest = (new DiactorosFactory())
  	->createRequest($symfonyRequest)
  	->withRequestTarget($symfonyRequest->getRequestUri());


Contributing
---------------

Pull Requests are welcome.

- [draft10]: http://tools.ietf.org/html/draft-cavage-http-signatures-10
- [Symfony\Component\HttpFoundation\Request]: https://github.com/symfony/HttpFoundation/blob/master/Request.php
- [composer]: https://getcomposer.org/
- [package]: https://packagist.org/packages/liamdennehy/http-signatures
- [psr7]: http://www.php-fig.org/psr/psr-7/

License
----------

HTTP Signatures PHP library is licensed under [The MIT License (MIT)](LICENSE).
