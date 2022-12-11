<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use HttpSignatures\Tests\TestKeys;
use PHPUnit\Framework\TestCase;

class RsaKeyTest extends TestCase
{
    public function testParseX509()
    {
        $this->assertTrue(Key::isX509Certificate(TestKeys::rsaCert));
        $this->assertFalse(Key::isPrivateKey(TestKeys::rsaCert));
        $this->assertFalse(Key::isPublicKey(TestKeys::rsaCert));
        $this->assertTrue(Key::hasPublicKey(TestKeys::rsaCert));
        $this->assertFalse(Key::hasPrivateKey(TestKeys::rsaCert));
        $this->assertTrue(Key::hasPKIKey(TestKeys::rsaCert));
        $key = new Key('rsaCert', TestKeys::rsaCert);
        $publicKey = $key->getVerifyingKey();
        $this->assertEquals('asymmetric', $key->getClass());
        $this->assertEquals('rsa', $key->getType());
        $this->assertEquals(TestKeys::rsaPublicKey, $publicKey);
    }

    public function testParseRsaPublicKey()
    {
        $this->assertTrue(Key::hasPublicKey(TestKeys::rsaPublicKey));
        $this->assertFalse(Key::hasPrivateKey(TestKeys::rsaPublicKey));
        $this->assertFalse(Key::isPrivateKey(TestKeys::rsaPublicKey));
        $this->assertFalse(Key::isX509Certificate(TestKeys::rsaPublicKey));
        $this->assertTrue(Key::isPublicKey(TestKeys::rsaPublicKey));
        $key = new Key('rsaPubKey', TestKeys::rsaPublicKey);
        $publicKey = $key->getVerifyingKey();
        $this->assertEquals('asymmetric', $key->getClass());
        $this->assertEquals('rsa', $key->getType());
        $this->assertEquals(TestKeys::rsaPublicKey, $publicKey);
    }

    public function testParseRSAPrivateKey()
    {
        $this->assertTrue(Key::hasPrivateKey(TestKeys::rsaPrivateKey));
        $this->assertTrue(Key::isPKIKey(TestKeys::rsaPrivateKey));
        $this->assertTrue(Key::isPrivateKey(TestKeys::rsaPrivateKey));
        $this->assertTrue(Key::hasPublicKey(TestKeys::rsaPrivateKey));
        $this->assertFalse(Key::isPublicKey(TestKeys::rsaPrivateKey));
        $key = new Key('TestRSAKey', TestKeys::rsaPrivateKey);
        $this->assertEquals(
            'asymmetric',
            $key->getClass()
        );
        $this->assertEquals(
            'rsa',
            $key->getType()
        );
        $this->assertEquals(
            TestKeys::rsaPrivateKey,
            $key->getSigningKey('PKCS1')
        );
    }

    public function testFetchRsaSigningKeySuccess()
    {
        $key = new Key('rsakey', TestKeys::rsaPrivateKey);
        $this->assertEquals(
            ['rsakey', TestKeys::rsaPrivateKey, TestKeys::rsaPublicKey, 'asymmetric'],
            [$key->getId(), $key->getSigningKey('PKCS1'), $key->getVerifyingKey(), $key->getClass()]
        );
    }

    public function testFetchRsaVerifyingKeyFromCertificateSuccess()
    {
        $key = new Key('rsacert', TestKeys::rsaCert);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(
            ['rsacert', null, TestKeys::rsaPublicKey, 'asymmetric'],
            [$key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getClass()]
        );
    }

    public function testFetchRsaVerifyingKeyFromPublicKeySuccess()
    {
        $key = new Key('rsapubkey', TestKeys::rsaPublicKey);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(
            ['rsapubkey', null, TestKeys::rsaPublicKey, 'asymmetric'],
            [$key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getClass()]
        );
    }

    public function testFetchRsaBothSuccess()
    {
        $key = new Key('rsaboth', [TestKeys::rsaCert, TestKeys::rsaPrivateKey]);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $keyStoreSigningKey = $key->getSigningKey('PKCS1');
        $this->assertEquals(
            ['rsaboth', TestKeys::rsaPrivateKey, TestKeys::rsaPublicKey, 'asymmetric'],
            [$key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getClass()]
        );
    }

    public function testFetchRsaBothSuccessSwitched()
    {
        $key = new Key('rsabothswitch', [TestKeys::rsaPrivateKey, TestKeys::rsaCert]);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $keyStoreSigningKey = $key->getSigningKey('PKCS1');
        $this->assertEquals(
            ['rsabothswitch', TestKeys::rsaPrivateKey, TestKeys::rsaPublicKey, 'asymmetric'],
            [$key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getClass()]
        );
    }

    // TODO: RSA mismatched keys not detected
    // public function testRsaMismatch()
    // {
    //     $privateKey = openssl_pkey_new([
    //       'private_key_type' => 'OPENSSL_KEYTYPE_RSA',
    //       'private_key_bits' => 512, ]
    //     );
    //     $this->expectException(\HttpSignatures\KeyException::class);
    //     $ks = new Key('badpki', [TestKeys::rsaPublicKey, $privateKey]);
    // }
}
