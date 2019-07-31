<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Verifier
{
    /** @var KeyStoreInterface */
    private $keyStore;

    /**
     * @param KeyStoreInterface $keyStore
     */
    public function __construct(KeyStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isSigned($message)
    {
        try {
            $verification = new Verification($message, $this->keyStore, 'Signature');

            return $verification->verify();
        } catch (\HttpSignatures\HeaderException $e) {
            return false;
        }
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isAuthorized($message)
    {
        $verification = new Verification($message, $this->keyStore, 'Authorization');

        return $verification->verify();
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isValidDigest($message)
    {
        $bodyDigest = BodyDigest::fromMessage($message);

        return $bodyDigest->isValid($message);
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isSignedWithDigest($message)
    {
        if ($this->isValidDigest($message)) {
            if ($this->isSigned($message)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isAuthorizedWithDigest($message)
    {
        if ($this->isValidDigest($message)) {
            if ($this->isAuthorized($message)) {
                return true;
            }
        }

        return false;
    }

    public function keyStore()
    {
        return $this->keyStore;
    }
}
