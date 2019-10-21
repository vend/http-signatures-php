<?php

namespace HttpSignatures;

use phpseclib\Crypt\RSA;

class RsaAlgorithm implements AlgorithmInterface
{
    /** @var string */
    private $digestName;

    /**
     * @param string $digestName
     */
    public function __construct($digestName)
    {
        $this->digestName = $digestName;
    }

    /**
     * @return string
     */
    public function name()
    {
        return sprintf('rsa-%s', $this->digestName);
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     *
     * @throws \HttpSignatures\AlgorithmException
     */
    public function sign($signingKey, $data)
    {
        $rsa = new RSA();
        $rsa->loadKey($signingKey);
        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $rsa->setHash($this->digestName);
        $signature = $rsa->sign($data);
        return $signature;
    }

    public function verify($message, $signature, $verifyingKey)
    {
        $algo = $this->getRsaHashAlgo($this->digestName);

        return 1 === openssl_verify($message, base64_decode($signature), $verifyingKey, $algo);
    }

    private function getRsaHashAlgo($digestName)
    {
        switch ($digestName) {
        case 'sha256':
            return OPENSSL_ALGO_SHA256;
        case 'sha1':
            return OPENSSL_ALGO_SHA1;
        default:
            throw new HttpSignatures\AlgorithmException($digestName.' is not a supported hash format');
      }
    }
}
