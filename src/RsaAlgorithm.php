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
        $rsa = new RSA();
        $rsa->loadKey($verifyingKey);
        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $rsa->setHash($this->digestName);
        try {
            $valid = $rsa->verify($message, base64_decode($signature));

            return $valid;
        } catch (\Exception $e) {
            if ('Invalid signature' != $e->getMessage()) {
                // Unhandled error state
                throw $e;
            } else {
                // Tolerate malformed signature
                return false;
            }
        }
    }
}
