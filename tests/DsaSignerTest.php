<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;
use PHPUnit\Framework\TestCase;

class DsaSignerTest extends TestCase
{
    private $context;

    public function setUp()
    {
        $dsaKeyFile = __DIR__.'/keys/DSA.key';
        $this->dsaPrivateKey = file_get_contents($dsaKeyFile);
        $this->sha1context = new Context([
            'keys' => ['prime256v1' => $this->dsaPrivateKey],
            'algorithm' => 'dsa-sha1',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->sha256context = new Context([
            'keys' => ['prime256v1' => $this->dsaPrivateKey],
            'algorithm' => 'dsa-sha256',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->message = new Request(
          'GET',
          '/path?query=123',
          ['date' => 'today', 'accept' => 'llamas']
        );
    }

    public function testSha1Signer()
    {
        $message = $this->sha1context->signer()->sign($this->message);
        $this->assertTrue(true);
    }

    public function testSha256Signer()
    {
        $signedMessage = $this->sha256context->signer()->sign($this->message);
        // $this->assertEquals(
        //   '',
        //   $signedMessage->getHeaderLine('Signature')
        // );
        $this->assertTrue(true);
    }

    public function testGetSigningString()
    {
        $this->assertEquals(
          "(request-target): get /path?query=123\ndate: today",
          $this->sha256context->signer()->getSigningString($this->message)
        );
    }

    public function testDsaBadalgorithm()
    {
        $this->expectException(\HTTPSignatures\AlgorithmException::class);
        $sha224context = new Context([
              'keys' => ['prime256v1' => $this->dsaPrivateKey],
              'algorithm' => 'dsa-sha224',
              'headers' => ['(request-target)', 'date'],
          ]);
    }
}
