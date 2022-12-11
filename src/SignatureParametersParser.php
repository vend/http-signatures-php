<?php

namespace HttpSignatures;

class SignatureParametersParser
{
    /** @var string */
    private $input;

    /**
     * @param string $input
     */
    public function __construct($input)
    {
        $this->input = $input;
    }

    /**
     * @return array
     */
    public function parse()
    {
        $result = $this->pairsToAssociative(
            $this->arrayOfPairs()
        );
        $this->validate($result);

        return $result;
    }

    /**
     * @param array $pairs
     *
     * @return array
     */
    private function pairsToAssociative($pairs)
    {
        $result = [];
        foreach ($pairs as $pair) {
            $result[$pair[0]] = $pair[1];
        }

        return $result;
    }

    /**
     * @return array
     */
    private function arrayOfPairs()
    {
        return array_map(
            [$this, 'pair'],
            $this->segments()
        );
    }

    /**
     * @return array
     */
    private function segments()
    {
        return explode(',', $this->input);
    }

    /**
     * @return array
     *
     * @throws SignatureParseException
     */
    private function pair($segment)
    {
        $segmentPattern = '/\A(keyId|algorithm|headers|signature)="(.*)"\z/';
        $matches = [];
        $result = preg_match($segmentPattern, $segment, $matches);
        if (1 !== $result) {
            // TODO: This is not strictly required, unknown parameters should be ignored
            // @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#section-2.2
            throw new SignatureParseException("Signature parameters segment '$segment' invalid");
        }
        array_shift($matches);

        return $matches;
    }

    /**
     * @throws SignatureParseException
     */
    private function validate($result)
    {
        $this->validateAllKeysArePresent($result);
    }

    /**
     * @throws SignatureParseException
     */
    private function validateAllKeysArePresent($result)
    {
        // Regexp in pair() ensures no unwanted keys exist.
        // Ensure that all mandatory keys exist.
        $wanted = ['keyId', 'algorithm', 'signature'];
        $missing = array_diff($wanted, array_keys($result));
        if (!empty($missing)) {
            $csv = implode(', ', $missing);
            throw new SignatureParseException("Missing keys $csv");
        }
    }
}
