<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\KeyStore;
use HttpSignatures\Verifier;
use PHPUnit\Framework\TestCase;

class VerifierEcTest extends TestCase
{
    public const DATE = 'Fri, 01 Aug 2014 13:44:32 -0700';
    public const DATE_DIFFERENT = 'Fri, 01 Aug 2014 13:44:33 -0700';

    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * @var Request
     */
    private $message;

    private $p256PublicKey;

    private $sha256SignedMessage;

    private $sha256AuthorizedMessage;

    public function setUp(): void
    {
        $this->setUpEcVerifier();
        $baseMessage = new Request('GET', '/path?query=123', [
            'Date' => 'today', ]);

        $sha256SignatureHeader =
        'keyId="prime256v1",'.
        'algorithm="ec-sha256",'.
        'headers="(request-target) date",'.
        'signature="MEYCIQCYqIngrRdn5gVFinJuIOCLn83x/QRzw3TgY70opOaIvgIhAOODGT'.
        '9UBf952e7vd7dMsv4GeYU0x1r+seEQV2R2Ly1Q"';

        $this->sha256SignedMessage =
          $baseMessage->withHeader('Signature', $sha256SignatureHeader);

        $this->sha256AuthorizedMessage =
          $baseMessage->withHeader('Authorization', 'Signature '.$sha256SignatureHeader);
    }

    private function setUpEcVerifier()
    {
        $p256PublicKeyFile = __DIR__.'/keys/prime256v1.named.pub';
        $this->p256PublicKey = file_get_contents($p256PublicKeyFile);
        $keyStore = new KeyStore(['prime256v1' => $this->p256PublicKey]);
        $this->verifier = new Verifier($keyStore);
    }

    public function testSha256Verifier()
    {
        $keyStore = new KeyStore(['prime256v1' => $this->p256PublicKey]);
        $this->verifier = new Verifier($keyStore);

        $this->assertTrue($this->verifier->isSigned($this->sha256SignedMessage));
        $this->assertEquals(
            "Message SigningString: 'KHJlcXVlc3QtdGFyZ2V0KTogZ2V0IC9wYXRoP3F1ZXJ5PTEyMwpkYXRlOiB0b2RheQ=='",
            $this->verifier->getStatus()[0]
        );
    }

    public function testVerifyAuthorizedEcMessage()
    {
        // $this->assertTrue($this->verifier->isAuthorized($this->sha1AuthorizedMessage));
        $this->assertTrue($this->verifier->isAuthorized($this->sha256AuthorizedMessage));
    }

    public function testRejectTamperedEcRequestMethod()
    {
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withMethod('POST')
        ));
    }

    public function testRejectTamperedEcDate()
    {
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withHeader('Date', self::DATE_DIFFERENT)
        ));
    }

    public function testRejectTamperedSignature()
    {
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withHeader(
                'Signature',
                preg_replace(
                    '/signature="/',
                    'signature="x',
                    $this->sha256SignedMessage->getHeader('Signature')[0]
                )
            )
        )
        );
    }

    public function testRejectEcMessageWithoutSignatureHeader()
    {
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withoutHeader('Signature')
        ));
    }

    public function testRejectEcMessageWithGarbageSignatureHeader()
    {
        $this->assertFalse(
            $this->verifier->isSigned(
                $this->sha256SignedMessage->withHeader('Signature', 'not="a",valid="signature"')
            )
        );
    }

    public function testRejectEcMessageWithPartialSignatureHeader()
    {
        $this->assertFalse(
            $this->verifier->isSigned(
                $this->sha256SignedMessage->withHeader('Signature', 'keyId="aa",algorithm="bb"')
            )
        );
    }

    public function testRejectsEcMessageWithUnknownKeyId()
    {
        $keyStore = new KeyStore(['nope' => 'secret']);
        $verifier = new Verifier($keyStore);
        // $this->assertFalse($verifier->isSigned($this->sha1SignedMessage));
        $this->assertFalse($verifier->isSigned($this->sha256SignedMessage));
        $this->assertEquals(
            "Cannot locate key for supplied keyId 'prime256v1'",
            $verifier->getStatus()[0]
        );
        $verifier->isSigned($this->sha256SignedMessage);
        $this->assertEquals(
            1,
            sizeof($verifier->getStatus())
        );
    }

    public function testRejectsEcMessageMissingSignedHeaders()
    {
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withoutHeader('Date')
        ));
    }
}
