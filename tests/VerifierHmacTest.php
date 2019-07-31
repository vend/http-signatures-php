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
        $this->setUpValidMessages();
        $this->setUpValidMessagesNoHeaders();
    }

    private function setUpVerifier()
    {
        $keyStore = new KeyStore(['secret1' => 'secret']);
        $this->verifier = new Verifier($keyStore);
    }

    private function setUpValidMessages()
    {
        $signatureHeader = sprintf(
            'keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'secret1',
            'hmac-sha256',
            '(request-target) date digest',
            'tcniMTUZOzRWCgKmLNAHag0CManFsj25ze9Skpk4q8c='
        );

        $this->signedMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Signature' => $signatureHeader,
            'Digest' => 'SHA-256=h7gWacNDycTMI1vWH4Z3f3Wek1nNZS8px82bBQEEARI=',
        ], 'Some body (though any body in a GET should be ignored)');

        $this->authorizedMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Authorization' => 'Signature '.$signatureHeader,
            'Digest' => 'SHA-256=h7gWacNDycTMI1vWH4Z3f3Wek1nNZS8px82bBQEEARI=',
        ], 'Some body (though any body in a GET should be ignored)');
    }

    private function setUpValidMessagesNoHeaders()
    {
        $signatureHeaderNoHeaders = sprintf(
            'keyId="%s",algorithm="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            'SNERdFCcPF40c5kw0zbmSXn3Zv2KZWhiuHSijhZs/4k='
        );

        $this->signedMessageNoHeaders = new Request('GET', '/path?query=123', [
            'Date' => 'today',
            'Signature' => $signatureHeaderNoHeaders,
            'NoSignatureHeaders' => 'true',
        ]);

        $this->authorizedMessageNoHeaders = new Request('GET', '/path?query=123', [
            'Date' => 'today',
            'Authorization' => 'Signature'.$signatureHeaderNoHeaders,
            'NoSignatureHeaders' => 'true',
        ]);
    }

    public function testVerifyValidMessage()
    {
        $this->assertTrue(
          $this->verifier->isSigned(
            $this->signedMessage
          )
        );
    }

    // TODO Follow flow to find out why this breaks
    // public function testVerifyValidMessageNoHeaders()
    // {
    //     $this->assertTrue($this->verifier->isSigned($this->validMessageNoHeaders));
    // }

    public function testVerifyValidDigest()
    {
        $this->assertTrue($this->verifier->isValidDigest($this->signedMessage));
    }

    public function testVerifyValidWithDigest()
    {
        $this->assertTrue($this->verifier->isSignedWithDigest($this->signedMessage));
        $this->assertTrue($this->verifier->isAuthorizedWithDigest($this->authorizedMessage));
    }

    public function testRejectBadDigest()
    {
        // $message = $this->validMessage->withoutHeader('Digest')
        //   ->withHeader('Digest', 'SHA-256=xxx');
        $this->assertFalse($this->verifier->isValidDigest(
          $this->signedMessage->withoutHeader('Digest')
            ->withHeader('Digest', 'SHA-256=xxx')
        ));
    }

    /**
     * @expectedException \HttpSignatures\DigestException
     */
    public function testRejectBadDigestName()
    {
        $message = $this->signedMessage->withoutHeader('Digest')
          ->withHeader('Digest', 'SHA-255=xxx');
        $this->assertFalse($this->verifier->isValidDigest($message));
    }

    /**
     * @expectedException \HttpSignatures\DigestException
     */
    public function testRejectBadDigestLine()
    {
        $message = $this->signedMessage->withoutHeader('Digest')
          ->withHeader('Digest', 'h7gWacNDycTMI1vWH4Z3f3Wek1nNZS8px82bBQEEARI=');
        $this->assertFalse($this->verifier->isValidDigest($message));
    }

    // TODO: Handle no 'headers' parameter
    // public function testVerifyMessagesNoHeaders()
    // {
    //     $this->assertTrue($this->verifier->isSigned($this->signedMessageNoHeaders));
    //     $this->assertTrue($this->verifier->isAuthorized($this->authorizedMessageNoHeaders));
    // }

    public function testVerifyAuthorized()
    {
        // $message = $this->validMessage->withHeader(
        //   'Authorization',
        //   'Signature '.$this->validMessage->getHeader('Signature')[0]
        //   );
        // $message = $message->withoutHeader('Signature');

        $this->assertTrue($this->verifier->isAuthorized($this->authorizedMessage));
    }

    public function testRejectTamperedHmacRequestMethod()
    {
        // $message = $this->signedMessage->withMethod('POST');
        $this->assertFalse($this->verifier->isSigned(
          $this->signedMessage->withMethod('POST')
        ));
    }

    public function testRejectTamperedHmacDate()
    {
        $message = $this->signedMessage->withHeader('Date', self::DATE_DIFFERENT);
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectTamperedHmacSignature()
    {
        $message = $this->signedMessage->withHeader(
            'Signature',
            preg_replace('/signature="/', 'signature="x', $this->signedMessage->getHeader('Signature')[0])
        );
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectHmacMessageWithoutSignatureHeader()
    {
        $message = $this->signedMessage->withoutHeader('Signature');
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectHmacMessageWithGarbageSignatureHeader()
    {
        $message = $this->signedMessage->withHeader('Signature', 'not="a",valid="signature"');
        $this->expectException("HttpSignatures\SignatureParseException");
        $this->verifier->isSigned($message);
    }

    public function testRejectHmacMessageWithPartialSignatureHeader()
    {
        $message = $this->signedMessage->withHeader('Signature', 'keyId="aa",algorithm="bb"');
        $this->expectException("HttpSignatures\SignatureParseException");
        $this->verifier->isSigned($message);
    }

    public function testRejectsHmacMessageWithUnknownKeyId()
    {
        $keyStore = new KeyStore(['nope' => 'secret']);
        $verifier = new Verifier($keyStore);
        $this->assertFalse($verifier->isSigned($this->signedMessage));
    }

    public function testRejectsHmacMessageMissingSignedHeaders()
    {
        $message = $this->signedMessage->withoutHeader('Date');
        $this->assertFalse($this->verifier->isSigned($message));
    }
}
