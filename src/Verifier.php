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
        $verification = new Verification($message, $this->keyStore);

        return $verification->isSigned();
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isAuthorized($message)
    {
        $verification = new Verification($message, $this->keyStore);

        return $verification->isAuthorized();
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
    public function isValidWithDigest($message)
    {
        if ($message->hasHeader('Digest')) {
            $spp = new SignatureParametersParser($message->getHeader('Signature')[0]);
            if (in_array('digest', explode(' ', $spp->parse()['headers']))) {
                $bodyDigest = BodyDigest::fromMessage($message);
                if ($bodyDigest->isValid($message)) {
                    return $this->isValid($message);
                }
            }
        }

        return false;
    }
}
