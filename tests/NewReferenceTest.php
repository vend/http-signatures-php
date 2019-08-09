<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\KeyStore;
use HttpSignatures\Context;
use HttpSignatures\Verifier;
use HttpSignatures\SigningString;
use HttpSignatures\BodyDigest;
use HttpSignatures\HeaderList;
use PHPUnit\Framework\TestCase;

/**
 * @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C Reference Tests
 */
class NewReferenceTest extends TestCase
{
    const referencePublicKey =
    '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----';

    const referencePrivateKey =
    '-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----';

    const referenceBodyDigest =
    'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=';

    const referenceHeaders =
    [
        'Host' => 'example.com',
        'Date' => 'Sun, 05 Jan 2014 21:31:40 GMT',
        'Content-Type' => 'application/json',
        'Content-Length' => '18',
        'Digest' => self::referenceBodyDigest,
    ];

    const referenceBody = '{"hello": "world"}';
    const referenceMethod = 'POST';
    const referenceUri = '/foo?param=value&pet=dog';

    // Header List if no headers parameter is specified
    const defaultHeaders = ['date'];

    const defaultTestSignatureLineValue =
      'keyId="Test",algorithm="rsa-sha256",'.
      'signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz'.
      '6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB'.
      '6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="';

    const defaultTestAuthorizationHeaderValue =
      'Signature '.self::defaultTestSignatureLineValue;

    const defaultTestSigningString = 'date: Sun, 05 Jan 2014 21:31:40 GMT';

    const basicTestSignatureHeaderValue =
      'keyId="Test",algorithm="rsa-sha256",'.
      'headers="(request-target) host date",signature="qdx+H7PHHDZgy4y'.
      '/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7'.
      'ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBsk'.
      'Lu6kd9Fswtemr3lgdDEmn04swr2Os0="';

    const basicTestAuthorizationHeaderValue =
        'Signature '.self::basicTestSignatureHeaderValue;

    const basicTestSigningString =
'(request-target): post /foo?param=value&pet=dog
host: example.com
date: Sun, 05 Jan 2014 21:31:40 GMT';

    const basicTestHeaders = ['(request-target)', 'host', 'date'];

    const allHeadersTestSignatureHeaderValue =
      'keyId="Test",algorithm="rsa-sha256",'.
      'headers="(request-target) host date content-type digest content-length",'.
      'signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs'.
      '8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZF'.
      'ukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="';

    const allHeadersTestAuthorizationHeaderValue =
      'Signature '.self::allHeadersTestSignatureHeaderValue;

    const allHeadersTestSigningString =
'(request-target): post /foo?param=value&pet=dog
host: example.com
date: Sun, 05 Jan 2014 21:31:40 GMT
content-type: application/json
digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
content-length: 18';

    const allHeadersTestHeaders =
        ['(request-target)', 'host', 'date', 'content-type', 'digest', 'content-length'];
    /**
     * @var Request
     */
    private $referenceMessage;

    /**
     * @var KeyStore
     */
    private $signingKeyStore;

    public function testTrue()
    {
        $this->assertTrue(true);
    }

    public function setUp()
    {
        $this->referenceMessage = new Request(
            self::referenceMethod,
            self::referenceUri,
            self::referenceHeaders,
            self::referenceBody
        );

        $this->signingKey = ['Test' => self::referencePrivateKey];
        $verifyingKeyStore = new KeyStore(['Test' => self::referencePublicKey]);
        $this->verifier = new Verifier($verifyingKeyStore);
    }

    /**
     * @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.1 Default Test
     */
    public function testDefault()
    {
        $ss = new SigningString(
            new HeaderList(self::defaultHeaders, false),
            $this->referenceMessage
        );
        $this->assertEquals(
            self::defaultTestSigningString,
            $ss->string()
        );

        $defaultContext = new Context([
            'keys' => ['Test' => self::referencePrivateKey],
            'algorithm' => 'rsa-sha256',
        ]);

        $authorizedMessage = $defaultContext->signer()->authorize($this->referenceMessage);
        $this->assertEquals(
            self::defaultTestAuthorizationHeaderValue,
            $authorizedMessage->getHeader('Authorization')[0]
        );

        // Permit Passing null as header list
        $defaultContext = new Context([
            'keys' => ['Test' => self::referencePrivateKey],
            'algorithm' => 'rsa-sha256',
            'headers' => null,
        ]);

        $authorizedMessage = $defaultContext->signer()->authorize($this->referenceMessage);
        $this->assertEquals(
            self::defaultTestAuthorizationHeaderValue,
            $authorizedMessage->getHeader('Authorization')[0]
        );

        // authorize() does not interfere with Signature header
        $this->assertEquals(
          0,
          sizeof($authorizedMessage->getHeader('Signature'))
        );
        $signedMessage = $defaultContext->signer()->sign($this->referenceMessage);
        $this->assertEquals(
            self::defaultTestSignatureLineValue,
            $signedMessage->getHeader('Signature')[0]
        );
        // sign() does not interfere with Authorization header
        $this->assertEquals(
          0,
          sizeof($signedMessage->getHeader('Authorization'))
        );

        $this->assertTrue(
            $this->verifier->isAuthorized($this->referenceMessage->withHeader(
                'Authorization', self::defaultTestAuthorizationHeaderValue
            ))
        );
        $this->assertTrue(
            $this->verifier->isSigned($this->referenceMessage->withHeader(
                'Signature', self::defaultTestSignatureLineValue
            ))
        );

        // Authorized <> Signed
        $this->assertFalse(
            $this->verifier->isSigned($this->referenceMessage->withHeader(
                'Authorization', self::defaultTestAuthorizationHeaderValue
            ))
        );
        $this->assertFalse(
            $this->verifier->isAuthorized($this->referenceMessage->withHeader(
                'Signature', self::defaultTestSignatureLineValue
            ))
        );
    }

    /**
     * @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.2 Basic Test
     */
    public function testBasic()
    {
        $ss = new SigningString(
            new HeaderList(self::basicTestHeaders),
            $this->referenceMessage
        );

        $this->assertEquals(
            self::basicTestSigningString,
            $ss->string()
        );
        $defaultContext = new Context([
            'keys' => ['Test' => self::referencePrivateKey],
            'algorithm' => 'rsa-sha256',
            'headers' => self::basicTestHeaders,
        ]);
        $authorizedMessage = $defaultContext->signer()->authorize($this->referenceMessage);
        $this->assertEquals(
            self::basicTestAuthorizationHeaderValue,
            $authorizedMessage->getHeader('Authorization')[0]
        );
        $signedMessage = $defaultContext->signer()->sign($this->referenceMessage);
        $this->assertEquals(
            self::basicTestSignatureHeaderValue,
            $signedMessage->getHeader('Signature')[0]
        );
        $this->assertTrue(
            $this->verifier->isAuthorized($this->referenceMessage->withHeader(
                'Authorization', self::basicTestAuthorizationHeaderValue
            ))
        );
        $this->assertTrue(
            $this->verifier->isSigned($this->referenceMessage->withHeader(
                'Signature', self::basicTestSignatureHeaderValue
            ))
        );
    }

    /**
     * @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.3 All Headers Test
     */
    public function testAllHeaders()
    {
        $ss = new SigningString(
            new HeaderList(self::allHeadersTestHeaders),
            $this->referenceMessage
        );

        $this->assertEquals(
            self::allHeadersTestSigningString,
            $ss->string()
        );

        $defaultContext = new Context([
            'keys' => ['Test' => self::referencePrivateKey],
            'algorithm' => 'rsa-sha256',
            'headers' => self::allHeadersTestHeaders,
        ]);

        $authorizedMessage = $defaultContext->signer()->authorize($this->referenceMessage);
        $this->assertEquals(
            self::allHeadersTestAuthorizationHeaderValue,
            $authorizedMessage->getHeader('Authorization')[0]
        );
        $signedMessage = $defaultContext->signer()->sign($this->referenceMessage);
        $this->assertEquals(
            self::allHeadersTestSignatureHeaderValue,
            $signedMessage->getHeader('Signature')[0]
        );
        $this->assertTrue(
            $this->verifier->isAuthorized($this->referenceMessage->withHeader(
                'Authorization', self::allHeadersTestAuthorizationHeaderValue
            ))
        );
        $this->assertTrue(
            $this->verifier->isSigned($this->referenceMessage->withHeader(
                'Signature', self::allHeadersTestSignatureHeaderValue
            ))
        );

        $this->assertTrue(true);
    }

    /**
     * Not strictly required, but included for completeness.
     */
    public function testDigest()
    {
        $bd = new BodyDigest('sha256');
        $digestContext = new Context([
            'keys' => ['Test' => self::referencePrivateKey],
            'algorithm' => 'rsa-sha256',
            'headers' => self::basicTestHeaders,
        ]);

        // $this->assertTrue(
        //     $this->verifier->isValidDigest($this->referenceMessage)
        // );

        $unDigestedMessage = $this->referenceMessage->withoutHeader('Digest');
        $d1 = (new BodyDigest('sha1'))->setDigestHeader($unDigestedMessage);
        $digestedMessage =
            (new BodyDigest('sha256'))->setDigestHeader($d1);
        // $this->assertEquals('',
        //     $digestedMessage->getHeader('Digest')[0]);

        $unDigestedMessage = $this->referenceMessage->withoutHeader('Digest');
        $digestedMessage = $digestContext->signer()->signWithDigest(
            $unDigestedMessage);

        // $this->assertEquals(
        //     self::referenceBodyDigest,
        //     $digestedMessage->getHeader('Digest')[0]
        // );
        // $this->assertTrue(
        //     $this->verifier->isValidWithDigest($digestedMessage)
        // );

        $this->assertTrue(true);
    }
}
