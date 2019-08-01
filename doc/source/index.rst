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
