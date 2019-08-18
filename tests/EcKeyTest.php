<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use HttpSignatures\KeyException;
use PHPUnit\Framework\TestCase;

class EcKeyTest extends TestCase
{
    public function setUp()
    {
        $this->opensslVersion = explode(' ', OPENSSL_VERSION_TEXT)[1];
        $this->opensslMajor = explode('.', $this->opensslVersion)[0];
        $this->opensslMinor = explode('.', $this->opensslVersion)[1];
        $this->opensslPatch = explode('.', $this->opensslVersion)[2];
        if ($this->opensslMajor < 1) {
            throw new Exception('OpenSSL library version < 1, cannot process EC keys', 1);
        }
    }

    public function testEcKeys()
    {
        $curves = [
          'secp256k1',
          'prime192v1',
        ];
        foreach ($curves as $curve) {
            $privateKeyData = file_get_contents(__DIR__."/keys/$curve.named.key");
            $key = new Key($curve, $privateKeyData);
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

            $publicKeyData = file_get_contents(__DIR__."/keys/$curve.named.pub");
            $key = new Key($curve, $publicKeyData);
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
        }
    }

    public function testParseAdvancedKeys()
    {
        if ($this->opensslMinor < 1) {
            $this->markTestSkipped(
              'OpenSSL '.$this->opensslVersion.
              ' probably doesn\'t understand later EC curves'
            );
        }
        $curves = [
          'ED25519',
          'ED448',
          'X25519',
          'X448',
        ];
        foreach ($curves as $curve) {
            $keyData = file_get_contents(__DIR__."/keys/$curve.key");
            // try {
            $key = new Key('key-ed25519', $keyData);
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

            $keyData = file_get_contents(__DIR__.'/keys/ED25519.pub');
            $key = new Key('key-ed25519', $publicKeyData);
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
            // } catch (KeyException $e) {
        //   $this->assertTrue(true);
        //   // $this->markTestSkipped("Unsupported EC Type $curve using OpenSSL " . $this->opensslVersion);
        //   // $this->expectException(KeyException::class);
        //   // throw new KeyException($e->getMessage(), 1);
        //
        // }
        }
    }
}
