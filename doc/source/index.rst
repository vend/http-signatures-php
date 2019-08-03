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

   quickstart
   reference/headers
   reference/api

Usage
============

Add `liamdennehy/http-signatures-php
<https://packagist.org/packages/liamdennehy/http-signatures-php>`_
to your ``composer.json``. Full instructions can be found in :ref:`installation`

To quickly see how a message is signed, take a look in :ref:`signing_quickstart`
in the Quickstart guide.

Requirements
============

#. PHP 5.6 (PHP >7.0 recommended)
#. Composer for full autoloading of class loading
#. Understanding of PSR-7 HTTP message handling

.. _installation:

Installation
---------------

The recommended way to install http-signatures-php is with
`Composer <http://getcomposer.org>`_. Composer is a dependency management tool
for PHP that allows you to declare the dependencies your project needs and
installs them into your project.

.. code-block:: sh

  # Install Composer
  curl -sS https://getcomposer.org/installer | php

You can add http-signatures-php as a dependency using the ``composer.phar`` CLI:

.. code-block:: sh

  php composer.phar require liamdennehy/http-signatures-php

Alternatively, you can specify http-signatures-php as a dependency
in your project's existing ``composer.json`` file:

.. code-block:: json

  {
    "require": {
       "liamdennehy/http-signatures-php": "~6.0"
    }
  }
  
After installing, you need to require Composer's autoloader in your project
to be able to locate the library within PHP:

.. code-block:: php

  require __DIR__ . '/vendor/autoload.php';

You can find out more on how to install Composer, configure autoloading, and
other best-practices for defining dependencies at `getcomposer.org <http://getcomposer.org>`_.


Contributing
============

Pull Requests are welcome, as are
`issue reports <https://github.com/liamdennehy/http-signatures-php/issues>`_
if you encounter any problems.

..
    - [draft10]: http://tools.ietf.org/html/draft-cavage-http-signatures-10
    - [Symfony\Component\HttpFoundation\Request]: https://github.com/symfony/HttpFoundation/blob/master/Request.php
    - [composer]: https://getcomposer.org/
    - [package]: https://packagist.org/packages/liamdennehy/http-signatures-php
    - [psr7]: http://www.php-fig.org/psr/psr-7/
    
License
============

HTTP Signatures PHP library is licensed under
`The MIT License (MIT) <https://opensource.org/licenses/MIT>`_

This documentation is licensed under
`Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)
<https://creativecommons.org/licenses/by-sa/4.0/>`_
