<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\KeyStore;
use HttpSignatures\Tests\TestKeys;
use HttpSignatures\Verifier;
use PHPUnit\Framework\TestCase;

class VerifierRsaTest extends TestCase
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

    private $sha256SignedMessage;

    private $sha256AuthorizedMessage;

    public function setUp(): void
    {
        $this->setUpRsaVerifier();
        $baseMessage = new Request('GET', '/path?query=123', [
            'Date' => 'today', ]);

        // TODO: Include multiple hash types for testing
        // $sha1SignatureHeader =
        // 'keyId="rsa1",algorithm="rsa-sha1",headers="(request-target) date",'.
        // 'signature="YIR3DteE3Jmz1VAnUMTgjTn3vTKfQuZl1CJhMBvGOZpnzwKeYBXAH10'.
        // '8FojnbSeVG/AXq9pcrA6AFK0peg0aueqxpaFlo+4L/q5XzJ+QoryY3dlSrxwVnE5s5'.
        // 'M19xmFm/6YkZR/KPeANCsG4SPL82Um/PCEMU0tmKd6sSx+IIzAYbXG/VrFMDeQAdXq'.
        // 'pU1EhgxopKEAapN8rChb49+1JfR/RxlSKiLukJJ6auurm2zMn2D40fR1d2umA5LAO7'.
        // 'vRt2iQwVbtwiFkVlRqkMvGftCNZByu8jJ6StI5H7EfuANSHAZXKXWNH8yxpBUW/QCH'.
        // 'CZjPd0ugM0QJJIc7i8JbGlA=="';
        //
        // $this->sha1SignedMessage = new Request('GET', '/path?query=123', [
        //     'Date' => 'today',
        //     'Signature' => $sha1SignatureHeader,
        // ]);

        $sha256SignatureHeader =
        'keyId="rsa1",algorithm="rsa-sha256",headers="(request-target) date",'.
        'signature="WGIegQCC3GEwxbkuXtq67CAqeDhkwblxAH2uoDx5kfWurhLRA5WBFDA/a'.
        'ktsZAjuUoimG1w4CGxSecziER1ez44PBlHP2fCW4ArLgnQgcjkdN2cOf/gj0OVL8s2us'.
        'G4o4tud/+jjF3nxTxLl3HC+erBKsJakwXbw9kt4Cr028BToVfNXsWoMFpv0IjcgBH2V4'.
        '1AVlX/mYBMMJAihBCIcpgAcGrrxmG2gkfvSn09wtTttkGHftPIp3VpB53zbemlJS9Yw3'.
        'tmmHr6cvWSXqQy/bTsEOoQJ2REfn5eiyzsJu3GiOpiILK67i/WH9moltJtlfV57TV72c'.
        'gYtjWa6yqhtFg=="';

        $this->sha256SignedMessage =
          $baseMessage->withHeader('Signature', $sha256SignatureHeader);

        $this->sha256AuthorizedMessage =
          $baseMessage->withHeader('Authorization', 'Signature '.$sha256SignatureHeader);
    }

    private function setUpRsaVerifier()
    {
        $keyStore = new KeyStore(['rsa1' => TestKeys::rsaCert]);
        $this->verifier = new Verifier($keyStore);
    }

    public function testVerifySignedRsaMessage()
    {
        // $this->assertTrue($this->verifier->isSigned($this->sha1SignedMessage));
        $this->assertTrue($this->verifier->isSigned($this->sha256SignedMessage));
    }

    public function testVerifyAuthorizedRsaMessage()
    {
        // $this->assertTrue($this->verifier->isAuthorized($this->sha1AuthorizedMessage));
        $this->assertTrue($this->verifier->isAuthorized($this->sha256AuthorizedMessage));
    }

    public function testRejectTamperedRsaRequestMethod()
    {
        // $this->assertFalse($this->verifier->isSigned(
        //     $this->sha1SignedMessage->withMethod('POST')
        // ));
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withMethod('POST')
        ));
    }

    public function testRejectTamperedRsaDate()
    {
        // $this->assertFalse($this->verifier->isSigned(
        //     $this->sha1SignedMessage->withHeader('Date', self::DATE_DIFFERENT)
        // ));
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withHeader('Date', self::DATE_DIFFERENT)
        ));
    }

    public function testRejectTamperedRsaSignature()
    {
        // $this->assertFalse($this->verifier->isSigned(
        //   $this->sha1SignedMessage->withHeader(
        //       'Signature',
        //       preg_replace(
        //         '/signature="/',
        //         'signature="x',
        //         $this->sha1SignedMessage->getHeader('Signature')[0]
        //       )
        //     )
        //   )
        // );

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

    public function testRejectRsaMessageWithoutSignatureHeader()
    {
        // $this->assertFalse($this->verifier->isSigned(
        //   $this->sha1SignedMessage->withoutHeader('Signature')
        // ));
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withoutHeader('Signature')
        ));
    }

    public function testRejectRsaMessageWithGarbageSignatureHeader()
    {
        // $this->expectException("HttpSignatures\SignatureParseException");
        // $this->verifier->isSigned(
        //   $this->sha1SignedMessage->withHeader('Signature', 'not="a",valid="signature"')
        // );
        $this->assertFalse(
            $this->verifier->isSigned(
                $this->sha256SignedMessage->withHeader('Signature', 'not="a",valid="signature"')
            )
        );
    }

    public function testRejectRsaMessageWithPartialSignatureHeader()
    {
        // $this->expectException("HttpSignatures\SignatureParseException");
        // $this->verifier->isSigned(
        //   $this->sha1SignedMessage->withHeader('Signature', 'keyId="aa",algorithm="bb"')
        // );
        $this->assertFalse(
            $this->verifier->isSigned(
                $this->sha256SignedMessage->withHeader('Signature', 'keyId="aa",algorithm="bb"')
            )
        );
    }

    public function testRejectsRsaMessageWithUnknownKeyId()
    {
        $keyStore = new KeyStore(['nope' => 'secret']);
        $verifier = new Verifier($keyStore);
        // $this->assertFalse($verifier->isSigned($this->sha1SignedMessage));
        $this->assertFalse($verifier->isSigned($this->sha256SignedMessage));
        $this->assertEquals(
            "Cannot locate key for supplied keyId 'rsa1'",
            $verifier->getStatus()[0]
        );
        $verifier->isSigned($this->sha256SignedMessage);
        $this->assertEquals(
            1,
            sizeof($verifier->getStatus())
        );
    }

    public function testRejectsRsaMessageMissingSignedHeaders()
    {
        // $this->assertFalse($this->verifier->isSigned(
        //   $this->sha1SignedMessage->withoutHeader('Date')
        // ));
        $this->assertFalse($this->verifier->isSigned(
            $this->sha256SignedMessage->withoutHeader('Date')
        ));
    }
}
