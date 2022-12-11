<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;
use HttpSignatures\Tests\TestKeys;
use PHPUnit\Framework\TestCase;

class RsaContextTest extends TestCase
{
    private $context;

    public function setUp(): void
    {
        $this->sha1context = new Context([
            'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
            'algorithm' => 'rsa-sha1',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->sha256context = new Context([
            'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
            'algorithm' => 'rsa-sha256',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->message = new Request('GET', '/path?query=123', ['date' => 'today', 'accept' => 'llamas']);
    }

    public function testSha1Signer()
    {
        $message = $this->sha1context->signer()->sign($this->message);
        $expectedSha1String = implode(',', [
            'keyId="rsa1"',
            'algorithm="rsa-sha1"',
            'headers="(request-target) date"',
            'signature="YIR3DteE3Jmz1VAnUMTgjTn3vTKfQuZl1CJhMBvGOZpnzwKeYBXA'.
              'H108FojnbSeVG/AXq9pcrA6AFK0peg0aueqxpaFlo+4L/q5XzJ+QoryY3dlSr'.
              'xwVnE5s5M19xmFm/6YkZR/KPeANCsG4SPL82Um/PCEMU0tmKd6sSx+IIzAYbX'.
              'G/VrFMDeQAdXqpU1EhgxopKEAapN8rChb49+1JfR/RxlSKiLukJJ6auurm2zM'.
              'n2D40fR1d2umA5LAO7vRt2iQwVbtwiFkVlRqkMvGftCNZByu8jJ6StI5H7Efu'.
              'ANSHAZXKXWNH8yxpBUW/QCHCZjPd0ugM0QJJIc7i8JbGlA=="',
        ]);

        $this->assertEquals(
            $expectedSha1String,
            $message->getHeader('Signature')[0]
        );
    }

    public function testSha256Signer()
    {
        $expectedDigestHeader = 'SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';

        $signedMessage = $this->sha256context->signer()->sign($this->message);
        $expectedSha256String = implode(',', [
            'keyId="rsa1"',
            'algorithm="rsa-sha256"',
            'headers="(request-target) date"',
            'signature="WGIegQCC3GEwxbkuXtq67CAqeDhkwblxAH2uoDx5kfWurhLRA5WB'.
            'FDA/aktsZAjuUoimG1w4CGxSecziER1ez44PBlHP2fCW4ArLgnQgcjkdN2cOf/g'.
            'j0OVL8s2usG4o4tud/+jjF3nxTxLl3HC+erBKsJakwXbw9kt4Cr028BToVfNXsW'.
            'oMFpv0IjcgBH2V41AVlX/mYBMMJAihBCIcpgAcGrrxmG2gkfvSn09wtTttkGHft'.
            'PIp3VpB53zbemlJS9Yw3tmmHr6cvWSXqQy/bTsEOoQJ2REfn5eiyzsJu3GiOpiI'.
            'LK67i/WH9moltJtlfV57TV72cgYtjWa6yqhtFg=="',
        ]);

        $this->assertEquals(
            $expectedSha256String,
            $signedMessage->getHeader('Signature')[0]
        );

        $signedWithDigestMessage = $this->sha256context->signer()->signWithDigest($this->message);

        $this->assertEquals(
            $expectedDigestHeader,
            $signedWithDigestMessage->getHeader('Digest')[0]
        );

        $authorizedWithDigestMessage = $this->sha256context->signer()->authorizeWithDigest($this->message);

        $this->assertEquals(
            $expectedDigestHeader,
            $authorizedWithDigestMessage->getHeader('Digest')[0]
        );
    }

    public function testGetSigningString()
    {
        $this->assertEquals(
          "(request-target): get /path?query=123\ndate: today",
          $this->sha256context->signer()->getSigningString($this->message)
        );
    }

    public function testRsaBadalgorithm()
    {
        $this->expectException(\HTTPSignatures\AlgorithmException::class);
        $sha224context = new Context([
              'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
              'algorithm' => 'rsa-sha224',
              'headers' => ['(request-target)', 'date'],
          ]);
    }

    public function testEmptyHeaders()
    {
        $emptyHeadersContext = new Context([
            'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
            'algorithm' => 'rsa-sha256',
            'headers' => [],
        ]);

        $signedMessage = $emptyHeadersContext->signer()->sign($this->message);
        $this->assertEquals(
          'keyId="rsa1",algorithm="rsa-sha256",signature="Mutm6x0apXqU6aQh36l'.
          '+/yEU0kSzKt8tEy6nxhBXJIv0kP+z9MWH0k7CgsLLt4RcGmf5i6qnmPkkKZ5ndLUL'.
          'FnXpFIQjs2aWaQ4Twq29no/acrkJA1S9zFJEIy9uI+UJurzlpWe3pTBdyAvF0PnMC'.
          '4IQJ0f7QRyWjMCSmHGKEv7iZGmt9l1l1zbx7DHeuaLCj1AIZlwhvw0bg+uk7NrgFG'.
          '2Vix1w707O/u8K3IrHFDDpbNBI2YmqklyAuoPtVe+DFlaC/G80ew3VyNU9lqNAQxL'.
          'eD0/O05xNNdJ7xjaaAPdv0VXYwzC70aek1ZY1RKlSmDi6x5k/clmtcWsqNx1RJw=="',
          $signedMessage->getHeader('Signature')[0]
        );
    }
}
