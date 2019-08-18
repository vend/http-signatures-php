<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use HttpSignatures\Key;
use PHPUnit\Framework\TestCase;

class KeyStoreHmacTest extends TestCase
{
    public function testHmacKeys()
    {
        $this->assertFalse(Key::hasPublicKey('secret'));
        $this->assertFalse(Key::isPKIKey('secret'));
        $this->assertFalse(Key::isX509Certificate('secret'));
        $key = new Key('pda', 'secret');
    }

    public function testFetchHmacSuccess()
    {
        $ks = new KeyStore(['hmacsecret' => 'ThisIsASecretKey']);
        $key = $ks->fetch('hmacsecret');
        $this->assertEquals(['hmacsecret', 'ThisIsASecretKey', 'ThisIsASecretKey', 'secret'], [
          $key->getId(), $key->getVerifyingKey(), $key->getSigningKey(), $key->getClass(), ]);
    }
}
