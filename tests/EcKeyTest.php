<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use HttpSignatures\KeyException;
use PHPUnit\Framework\TestCase;

class EcKeyTest extends TestCase
{
    public function testNamedEcKeys()
    {
        $curves = [
          // 'secp256k1',
          // 'prime192v1',
        ];
        if (empty($curves)) {
            $this->markTestSkipped('No supported curves');
        }
        foreach ($curves as $curve) {
            $privateKeyData = file_get_contents(__DIR__."/keys/$curve.named.key");
            $privateKey = new Key($curve, $privateKeyData);
            $this->assertEquals(
              $curve.': '.true,
              $curve.': '.Key::hasPublicKey($privateKey)
            );
            $this->assertEquals(
              $curve.' is asymmetric',
              $curve.' is '.$privateKey->getClass()
            );
            $this->assertEquals(
              $curve.' is ec',
              $curve.' is '.$privateKey->getType()
            );
            $this->assertEquals(
              $curve.' is '.$curve,
              $curve.' is '.$privateKey->getCurve()
            );
            $publicKeyData = file_get_contents(__DIR__."/keys/$curve.named.pub");
            $publicKey = new Key($curve, $publicKeyData);
            $this->assertEquals(
              $curve.' is asymmetric',
              $curve.' is '.$publicKey->getClass()
            );
            $this->assertEquals(
              $curve.' is ec',
              $curve.' is '.$publicKey->getType()
            );
            $this->assertEquals(
              $curve.' is '.$curve,
              $curve.' is '.$publicKey->getCurve()
            );
            $this->assertTrue(Key::hasPublicKey($publicKey));
        }
    }

    public function testParseAdvancedKeys()
    {
        $curves = [
          'secp256r1',
          'prime239v3',
          'Ed25519',
          // 'ED448',
          // 'X25519',
          // 'X448',
        ];
        if (empty($curves)) {
            $this->markTestSkipped('No supported curves');
        }
        foreach ($curves as $curve) {
            $privatekeyData = file_get_contents(__DIR__."/keys/$curve.key");
            $this->assertEquals(
              $curve.': '.'Is Private Key',
              $curve.': '.(Key::isPrivateKey($privatekeyData) ? 'Is Private Key' : 'Is Not Private Key')
            );
            $this->assertEquals(
              $curve.': '.'Has Public Key',
              $curve.': '.(Key::hasPublicKey($privatekeyData) ? 'Has Public Key' : 'Has No Public Key')
            );
            $this->assertEquals(
              $curve.': '.'Has Private Key',
              $curve.': '.(Key::hasPrivateKey($privatekeyData) ? 'Has Private Key' : 'Has No Private Key')
            );
            $key = new Key($curve, $privatekeyData);
            $this->assertEquals(
              $curve.' is asymmetric',
              $curve.' is '.$key->getClass()
            );
            $this->assertEquals(
              $curve.' is ec',
              $curve.' is '.$key->getType()
            );
            $this->assertEquals(
              $curve.' is '.$curve,
              $curve.' is '.$key->getCurve()
            );

            $publicKeyData = file_get_contents(__DIR__."/keys/$curve.pub");
            // print "aaaaa".$publicKeyData . PHP_EOL;
            $this->assertEquals(
              $curve.': '.'Has Public Key',
              $curve.': '.(Key::hasPublicKey($publicKeyData) ? 'Has Public Key' : 'Has No Public Key')
            );
            $this->assertEquals(
              $curve.': '.'Has No Private Key',
              $curve.': '.(Key::hasPrivateKey($publicKeyData) ? 'Has Private Key' : 'Has No Private Key')
            );
        }
    }
}
