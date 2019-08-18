<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use HttpSignatures\Tests\TestKeys;
use PHPUnit\Framework\TestCase;

class RsaKeyTest extends TestCase
{
    public function setUp()
    {
        openssl_pkey_export(
            openssl_pkey_get_private(TestKeys::rsaPrivateKey),
            $this->testRsaPrivateKeyPEM
        );
        $this->testRsaPublicKeyPEM = openssl_pkey_get_details(
            openssl_get_publickey(TestKeys::rsaPublicKey)
        )['key'];
        $this->testRsaCert = TestKeys::rsaCert;
    }

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
        $this->assertEquals(TestKeys::rsaPublicKey, $publicKey);
    }

    public function testParseRsaPublicKeyinObject()
    {
        $this->assertTrue(Key::hasPublicKey(TestKeys::rsaPublicKey));
        $this->assertFalse(Key::hasPrivateKey(TestKeys::rsaPublicKey));
        $this->assertFalse(Key::isX509Certificate(TestKeys::rsaPublicKey));
        $this->assertTrue(Key::isPublicKey(TestKeys::rsaPublicKey));

        $key = new Key('rsaPubKey', TestKeys::rsaPublicKey);
        $publicKey = $key->getVerifyingKey();
        $this->assertEquals('asymmetric', $key->getClass());
        $this->assertEquals(TestKeys::rsaPublicKey, $publicKey);
    }

    public function testParseRSAPrivateKey()
    {
        $this->assertTrue(Key::isPKIKey(TestKeys::rsaPrivateKey));
        $this->assertTrue(Key::isPrivateKey(TestKeys::rsaPrivateKey));
        $this->assertFalse(Key::isPublicKey(TestKeys::rsaPrivateKey));
        openssl_pkey_export(
          openssl_pkey_get_private(TestKeys::rsaPrivateKey),
          $expectedSigningKey
        );
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
          $expectedSigningKey,
          $key->getSigningKey()
        );
    }

    public function testFetchRsaSigningKeySuccess()
    {
        $key = new Key('rsakey', TestKeys::rsaPrivateKey);
        openssl_pkey_export($key->getSigningKey(), $keyStoreSigningKey);
        $this->assertEquals(['rsakey', $this->testRsaPrivateKeyPEM, null, 'asymmetric'], [
          $key->getId(), $keyStoreSigningKey, $key->getVerifyingKey(), $key->getClass(), ]);
    }

    public function testFetchRsaVerifyingKeyFromCertificateSuccess()
    {
        $key = new Key('rsacert', TestKeys::rsaCert);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(['rsacert', null, $this->testRsaPublicKeyPEM, 'asymmetric'], [
          $key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getClass(), ]);
    }

    public function testFetchRsaVerifyingKeyFromPublicKeySuccess()
    {
        $key = new Key('rsapubkey', TestKeys::rsaPublicKey);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(['rsapubkey', null, $this->testRsaPublicKeyPEM, 'asymmetric'], [
          $key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getClass(), ]);
    }

    public function testFetchRsaBothSuccess()
    {
        $key = new Key('rsaboth', [TestKeys::rsaCert, TestKeys::rsaPrivateKey]);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $keyStoreSigningKey = $key->getSigningKey();
        $this->assertEquals(['rsaboth', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM, 'asymmetric'], [
          $key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getClass(), ]);
    }

    public function testFetchRsaBothSuccessSwitched()
    {
        $key = new Key('rsabothswitch', [TestKeys::rsaPrivateKey, TestKeys::rsaCert]);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $keyStoreSigningKey = $key->getSigningKey();
        $this->assertEquals(['rsabothswitch', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM, 'asymmetric'], [
          $key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getClass(), ]);
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
