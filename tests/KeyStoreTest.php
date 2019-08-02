<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use PHPUnit\Framework\TestCase;
use HttpSignatures\Exception;

class KeyStoreTest extends TestCase
{
    public function testFetchFail()
    {
        $ks = new KeyStore(['id' => 'secret']);
        // TODO: Make this exception more specific. KeyException?
        $this->expectException(\HttpSignatures\Exception::class);
        $key = $ks->fetch('nope');
    }
}
