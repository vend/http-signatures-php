# HTTP Signatures

[![Build Status](https://travis-ci.org/liamdennehy/http-signatures-php.svg?branch=master)](https://travis-ci.org/liamdennehy/http-signatures-php)
[![Documentation Status](https://readthedocs.org/projects/http-signatures-php/badge/?version=latest)](https://http-signatures-php.readthedocs.io/en/latest/?badge=latest)

PHP implementation of [Singing HTTP Messages][draft10] draft specification;
allowing cryptographic signing and verifying of [PSR-7 messages][psr7].

<!-- See also:

* https://github.com/99designs/http-signatures-guzzlehttp
* https://github.com/99designs/http-signatures-ruby
-->

Complete documentation for this library can be found at 
[Read The Docs](https://http-signatures-php.readthedocs.io/en/latest/)

## Usage
---

Add [liamdennehy/http-signatures-php][package] to your [``composer.json``][composer].


* A message is assumed to be a PSR-7 compatible Request or Response objects.
* A ``Context`` object is used to configure the signature parameters, and prepare
  the verifier functionality.


## Contributing

Pull Requests are welcome, as are 
[issue reports][github] if you encounter any problems.

[draft10]: http://tools.ietf.org/html/draft-cavage-http-signatures-10
[Symfony\Component\HttpFoundation\Request]: https://github.com/symfony/HttpFoundation/blob/master/Request.php
[composer]: https://getcomposer.org/
[package]: https://packagist.org/packages/liamdennehy/http-signatures-php
[github]: https://github.com/liamdennehy/http-signatures-php/issues
[psr7]: http://www.php-fig.org/psr/psr-7/

## License

HTTP Signatures is licensed under [The MIT License (MIT)](LICENSE).
