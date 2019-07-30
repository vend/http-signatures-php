<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\KeyStore;
use HttpSignatures\Verifier;
use PHPUnit\Framework\TestCase;

class VerifierHmacTest extends TestCase
{
    const DATE = 'Fri, 01 Aug 2014 13:44:32 -0700';
    const DATE_DIFFERENT = 'Fri, 01 Aug 2014 13:44:33 -0700';

    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * @var Request
     */
    private $validMessage;

    /**
     * @var Request
     */
    private $validMessageNoHeaders;

    public function setUp()
    {
        $this->setUpVerifier();
        $this->setUpValidMessage();
        $this->setUpValidMessageNoHeaders();
    }

    private function setUpVerifier()
    {
        $keyStore = new KeyStore(['secret1' => 'secret']);
        $this->verifier = new Verifier($keyStore);
    }

    private function setUpValidMessage()
    {
        $signatureHeader = sprintf(
            'keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'secret1',
            'hmac-sha256',
            '(request-target) date digest',
            'tcniMTUZOzRWCgKmLNAHag0CManFsj25ze9Skpk4q8c='
        );

        $this->validMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Signature' => $signatureHeader,
            'Digest' => 'SHA-256=h7gWacNDycTMI1vWH4Z3f3Wek1nNZS8px82bBQEEARI=',
        ], 'Some body (though any body in a GET should be ignored)');
    }

    private function setUpValidMessageNoHeaders()
    {
        $signatureHeaderNoHeaders = sprintf(
            'keyId="%s",algorithm="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            'SNERdFCcPF40c5kw0zbmSXn3Zv2KZWhiuHSijhZs/4k='
        );

        $this->validMessageNoHeaders = new Request('GET', '/path?query=123', [
            'Date' => 'today',
            'Signature' => $signatureHeaderNoHeaders,
            'NoSignatureHeaders' => 'true',
        ]);
    }

    public function testVerifyValidMessage()
    {
        $this->assertTrue($this->verifier->isValid($this->validMessage));
    }

    // TODO Follow flow to find out why this breaks
    // public function testVerifyValidMessageNoHeaders()
    // {
    //     $this->assertTrue($this->verifier->isValid($this->validMessageNoHeaders));
    // }

    public function testVerifyValidDigest()
    {
        $this->assertTrue($this->verifier->isValidDigest($this->validMessage));
    }

    public function testVerifyValidWithDigest()
    {
        $this->assertTrue($this->verifier->isValidWithDigest($this->validMessage));
    }

    public function testRejectBadDigest()
    {
        $message = $this->validMessage->withoutHeader('Digest')
          ->withHeader('Digest', 'SHA-256=xxx');
        $this->assertFalse($this->verifier->isValidDigest($message));
    }

    /**
     * @expectedException \HttpSignatures\DigestException
     */
    public function testRejectBadDigestName()
    {
        $message = $this->validMessage->withoutHeader('Digest')
          ->withHeader('Digest', 'SHA-255=xxx');
        $this->assertFalse($this->verifier->isValidDigest($message));
    }

    /**
     * @expectedException \HttpSignatures\DigestException
     */
    public function testRejectBadDigestLine()
    {
        $message = $this->validMessage->withoutHeader('Digest')
          ->withHeader('Digest', 'h7gWacNDycTMI1vWH4Z3f3Wek1nNZS8px82bBQEEARI=');
        $this->assertFalse($this->verifier->isValidDigest($message));
    }

    public function testVerifyValidMessageAuthorizationHeader()
    {
        $message = $this->validMessage->withHeader(
          'Authorization',
          'Signature '.$this->validMessage->getHeader('Signature')[0]
          );
        $message = $message->withoutHeader('Signature');

        $this->assertTrue($this->verifier->isValid($this->validMessage));
    }

    public function testRejectTamperedHmacRequestMethod()
    {
        $message = $this->validMessage->withMethod('POST');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectTamperedHmacDate()
    {
        $message = $this->validMessage->withHeader('Date', self::DATE_DIFFERENT);
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectTamperedHmacSignature()
    {
        $message = $this->validMessage->withHeader(
            'Signature',
            preg_replace('/signature="/', 'signature="x', $this->validMessage->getHeader('Signature')[0])
        );
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectHmacMessageWithoutSignatureHeader()
    {
        $message = $this->validMessage->withoutHeader('Signature');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectHmacMessageWithGarbageSignatureHeader()
    {
        $message = $this->validMessage->withHeader('Signature', 'not="a",valid="signature"');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectHmacMessageWithPartialSignatureHeader()
    {
        $message = $this->validMessage->withHeader('Signature', 'keyId="aa",algorithm="bb"');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectsHmacMessageWithUnknownKeyId()
    {
        $keyStore = new KeyStore(['nope' => 'secret']);
        $verifier = new Verifier($keyStore);
        $this->assertFalse($verifier->isValid($this->validMessage));
    }

    public function testRejectsHmacMessageMissingSignedHeaders()
    {
        $message = $this->validMessage->withoutHeader('Date');
        $this->assertFalse($this->verifier->isValid($message));
    }
}
