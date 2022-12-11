<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use PHPUnit\Framework\TestCase;

class HmacKeyTest extends TestCase
{
    public function testHmacKeys()
    {
        $this->assertFalse(Key::hasPublicKey('ThisIsASecretKey'));
        $this->assertFalse(Key::isPKIKey('ThisIsASecretKey'));
        $this->assertFalse(Key::isX509Certificate('ThisIsASecretKey'));
        $key = new Key('hmacsecret', 'ThisIsASecretKey');
        $this->assertEquals(
            [
              'hmacsecret',
              'ThisIsASecretKey',
              'ThisIsASecretKey',
              'secret',
            ],
            [
              $key->getId(),
              $key->getVerifyingKey(),
              $key->getSigningKey(),
              $key->getClass(),
            ]
        );
    }
}
