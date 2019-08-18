<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use HttpSignatures\Tests\TestKeys;
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase
{
    public function testMixKeyTypes()
    {
        $this->expectException(\HttpSignatures\KeyException::class);
        $key = new Key('mixed', ['secret', TestKeys::rsaPrivateKey]);
    }
}
