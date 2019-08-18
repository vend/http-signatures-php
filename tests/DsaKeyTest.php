<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use PHPUnit\Framework\TestCase;

class DsaKeyTest extends TestCase
{
    public function setUp()
    {
    }

    public function testParseDSAKeys()
    {
        $keyData = file_get_contents(__DIR__.'/../reference/keys/dsa_pub.pem');
        $key = new Key('key-dsa', $keyData);
        $this->assertEquals(
          'asymmetric',
          $key->getClass()
        );
        $this->assertEquals(
          'dsa',
          $key->getType()
        );
    }
}
