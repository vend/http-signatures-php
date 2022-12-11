<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use PHPUnit\Framework\TestCase;

class DsaKeyTest extends TestCase
{
    public function setUp(): void
    {
    }

    public function testParseDSAKeys()
    {
        $keyData = file_get_contents(__DIR__.'/keys/DSA.key');
        $key = new Key('key-dsa', $keyData);
        $this->assertEquals(
            'asymmetric',
            $key->getClass()
        );
        $this->assertEquals(
            'dsa',
            $key->getType()
        );
        $keyData = file_get_contents(__DIR__.'/keys/DSA.pub');
        $key = new Key('key-dsa', $keyData);
        $this->assertEquals(
            'asymmetric',
            $key->getClass()
        );
        $this->assertEquals(
            'dsa',
            $key->getType()
        );
    }
}
