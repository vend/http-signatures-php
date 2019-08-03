<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use PHPUnit\Framework\TestCase;

class KeyStoreTest extends TestCase
{
    public function testFetchFail()
    {
        $ks = new KeyStore(['id' => 'secret']);
        // TODO: Make this exception more specific. KeyException?
        $this->expectException(\HttpSignatures\KeyStoreException::class);
        $key = $ks->fetch('nope');
    }
}
