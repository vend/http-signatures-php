<?php

namespace HttpSignatures\tests;

use HttpSignatures\SignatureParametersParser;
use HttpSignatures\SignatureParseException;
use PHPUnit\Framework\TestCase;

class SignatureParametersParserTest extends TestCase
{
    public function testParseReturnsExpectedAssociativeArray()
    {
        $parser = new SignatureParametersParser(
            'keyId="example",algorithm="hmac-sha1",headers="(request-target) date",signature="b64"'
        );
        $this->assertEquals(
            [
                'keyId' => 'example',
                'algorithm' => 'hmac-sha1',
                'headers' => '(request-target) date',
                'signature' => 'b64',
            ],
            $parser->parse()
        );
    }

    public function testParseThrowsTypedException()
    {
        $parser = new SignatureParametersParser('nope');
        $this->expectException(SignatureParseException::class);
        $parser->parse();
    }

    // TODO: Detect all missing mandatory parms
    public function testParseExceptionForMissingComponents()
    {
        $parser = new SignatureParametersParser(
            'keyId="example",algorithm="hmac-sha1",headers="(request-target) date"'
        );
        $this->expectException(SignatureParseException::class);
        $parser->parse();
    }
}
