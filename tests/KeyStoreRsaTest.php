<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use HttpSignatures\Key;
use HttpSignatures\Tests\TestKeys;
use PHPUnit\Framework\TestCase;

class KeyStoreRsaTest extends TestCase
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
        // $keySpec = ['rsaCert' => TestKeys::rsaCert];
        // $ks = new KeyStore($keySpec);
        $publicKey = $key->getVerifyingKey();
        // $publicKey = $ks->fetch('rsaCert')->getVerifyingKey();
        // $this->assertEquals('asymmetric', $ks->fetch('rsaCert')->getType());
        $this->assertEquals('asymmetric', $key->getType());
        $this->assertEquals(TestKeys::rsaPublicKey, $publicKey);
    }

    public function testParseRsaPublicKeyinObject()
    {
        $this->assertTrue(!empty(openssl_pkey_get_public(TestKeys::rsaPublicKey)));
        $keySpec = ['rsaPubKey' => [TestKeys::rsaPublicKey]];
        $this->assertTrue(Key::hasPublicKey(TestKeys::rsaPublicKey));
        $this->assertFalse(Key::hasPrivateKey(TestKeys::rsaPublicKey));
        $this->assertFalse(Key::isX509Certificate(TestKeys::rsaPublicKey));

        $this->assertTrue(Key::isPublicKey(TestKeys::rsaPublicKey));

        $ks = new KeyStore($keySpec);
        $publicKey = $ks->fetch('rsaPubKey')->getVerifyingKey();
        $this->assertEquals('asymmetric', $ks->fetch('rsaPubKey')->getType());
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
          $key->getType()
        );
        $this->assertEquals(
          'rsa',
          $key->getAlgorithm()
        );
        $this->assertEquals(
          $expectedSigningKey,
          $key->getSigningKey()
        );
    }

    public function testFetchRsaSigningKeySuccess()
    {
        $key = new Key('rsakey', TestKeys::rsaPrivateKey);
        $ks = new KeyStore(['rsakey' => TestKeys::rsaPrivateKey]);
        // $key = $ks->fetch('rsakey');
        openssl_pkey_export($key->getSigningKey(), $keyStoreSigningKey);
        $this->assertEquals(['rsakey', $this->testRsaPrivateKeyPEM, null, 'asymmetric'], [
          $key->getId(), $keyStoreSigningKey, $key->getVerifyingKey(), $key->getType(), ]);
    }

    public function testFetchRsaVerifyingKeyFromCertificateSuccess()
    {
        $key = new Key('rsacert', TestKeys::rsaCert);
        // $key = $ks->fetch('rsacert');
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(['rsacert', null, $this->testRsaPublicKeyPEM, 'asymmetric'], [
          $key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getType(), ]);
    }

    public function testFetchRsaVerifyingKeyFromPublicKeySuccess()
    {
        // $ks = new KeyStore(['rsapubkey' => TestKeys::rsaPublicKey]);
        // $key = $ks->fetch('rsapubkey');
        $key = new Key('rsapubkey', TestKeys::rsaPublicKey);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(['rsapubkey', null, $this->testRsaPublicKeyPEM, 'asymmetric'], [
          $key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getType(), ]);
    }

    public function testFetchRsaBothSuccess()
    {
        // $ks = new KeyStore(['rsaboth' => [TestKeys::rsaPrivateKey]]);
        // $ks = new KeyStore(['rsaboth' => [TestKeys::rsaCert, TestKeys::rsaPrivateKey]]);
        $key = new Key('rsaboth', [TestKeys::rsaCert, TestKeys::rsaPrivateKey]);
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $keyStoreSigningKey = $key->getSigningKey();
        $this->assertEquals(['rsaboth', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM, 'asymmetric'], [
          $key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getType(), ]);
    }

    public function testFetchRsaBothSuccessSwitched()
    {
        $ks = new KeyStore(['rsabothswitch' => [TestKeys::rsaPrivateKey, TestKeys::rsaCert]]);
        $key = $ks->fetch('rsabothswitch');
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $keyStoreSigningKey = $key->getSigningKey();
        $this->assertEquals(['rsabothswitch', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM, 'asymmetric'], [
          $key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getType(), ]);
    }

    public function testRsaMismatch()
    {
        $privateKey = openssl_pkey_new([
          'private_key_type' => 'OPENSSL_KEYTYPE_RSA',
          'private_key_bits' => 1024, ]
        );
        $this->expectException(\HttpSignatures\KeyException::class);
        $ks = new Key('badpki', [TestKeys::rsaCert, $privateKey]);
    }
}
