<?php

namespace HttpSignatures;

class SignatureParameters
{
    /**
     * @param Key                $key
     * @param AlgorithmInterface $algorithm
     * @param HeaderList         $headerList
     * @param Signature          $signature
     */
    public function __construct(
        private $key,
        private $algorithm,
        private $headerList,
        private $signature,
    ) {
    }

    /**
     * @return string
     */
    public function string()
    {
        return implode(',', $this->parameterComponents());
    }

    /**
     * @return array
     */
    private function parameterComponents()
    {
        $components = [];
        $components[] = sprintf('keyId="%s"', $this->key->getId());
        $components[] = sprintf('algorithm="%s"', $this->algorithm->name());
        if ($this->headerList->headerListSpecified()) {
            $components[] = sprintf('headers="%s"', $this->headerList->string());
        }
        $components[] = sprintf('signature="%s"', $this->signatureBase64());

        return $components;
    }

    /**
     * @return string
     */
    private function signatureBase64()
    {
        return base64_encode($this->signature->string());
    }
}
