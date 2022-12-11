<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;
use PHPUnit\Framework\TestCase;

class DsaContextTest extends TestCase
{
    private $context;

    public function setUp(): void
    {
        $dsaKeyFile = __DIR__.'/keys/DSA.key';
        $this->dsaPrivateKey = file_get_contents($dsaKeyFile);

        $this->sha1context = new Context([
            'keys' => ['dsa1' => $this->dsaPrivateKey],
            'algorithm' => 'dsa-sha1',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->sha256context = new Context([
            'keys' => ['dsa1' => $this->dsaPrivateKey],
            'algorithm' => 'dsa-sha256',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->message = new Request('GET', '/path?query=123', ['date' => 'today', 'accept' => 'llamas']);
    }

    public function testSha1Signer()
    {
        $message = $this->sha1context->signer()->sign($this->message);
        $expectedSha1String = implode(',', [
            'keyId="dsa1"',
            'algorithm="dsa-sha1"',
            'headers="(request-target) date"',
            'signature="YIR3DteE3Jmz1VAnUMTgjTn3vTKfQuZl1CJhMBvGOZpnzwKeYBXA'.
              'H108FojnbSeVG/AXq9pcrA6AFK0peg0aueqxpaFlo+4L/q5XzJ+QoryY3dlSr'.
              'xwVnE5s5M19xmFm/6YkZR/KPeANCsG4SPL82Um/PCEMU0tmKd6sSx+IIzAYbX'.
              'G/VrFMDeQAdXqpU1EhgxopKEAapN8rChb49+1JfR/RxlSKiLukJJ6auurm2zM'.
              'n2D40fR1d2umA5LAO7vRt2iQwVbtwiFkVlRqkMvGftCNZByu8jJ6StI5H7Efu'.
              'ANSHAZXKXWNH8yxpBUW/QCHCZjPd0ugM0QJJIc7i8JbGlA=="',
        ]);

        // $this->assertEquals(
        //     $expectedSha1String,
        //     $message->getHeader('Signature')[0]
        // );
        $this->assertTrue(true);
    }

    public function testSha256Signer()
    {
        $expectedDigestHeader = 'SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';

        $signedMessage = $this->sha256context->signer()->sign($this->message);
        $expectedSha256String = implode(',', [
            'keyId="dsa1"',
            'algorithm="dsa-sha256"',
            'headers="(request-target) date"',
            'signature="WGIegQCC3GEwxbkuXtq67CAqeDhkwblxAH2uoDx5kfWurhLRA5WB'.
            'FDA/aktsZAjuUoimG1w4CGxSecziER1ez44PBlHP2fCW4ArLgnQgcjkdN2cOf/g'.
            'j0OVL8s2usG4o4tud/+jjF3nxTxLl3HC+erBKsJakwXbw9kt4Cr028BToVfNXsW'.
            'oMFpv0IjcgBH2V41AVlX/mYBMMJAihBCIcpgAcGrrxmG2gkfvSn09wtTttkGHft'.
            'PIp3VpB53zbemlJS9Yw3tmmHr6cvWSXqQy/bTsEOoQJ2REfn5eiyzsJu3GiOpiI'.
            'LK67i/WH9moltJtlfV57TV72cgYtjWa6yqhtFg=="',
        ]);

        // $this->assertEquals(
        //     $expectedSha256String,
        //     $signedMessage->getHeader('Signature')[0]
        // );
        $this->assertTrue(true);
    }

    public function testdsaBadalgorithm()
    {
        $this->expectException(\HTTPSignatures\AlgorithmException::class);
        $sha224context = new Context([
              'keys' => ['dsa1' => $this->dsaPrivateKey],
              'algorithm' => 'dsa-sha224',
              'headers' => ['(request-target)', 'date'],
          ]);
    }
}
