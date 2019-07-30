<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use PHPUnit\Framework\TestCase;

class KeyStoreTest extends TestCase
{
    /**
     * @expectedException \HttpSignatures\Exception
     */
    public function testFetchFail()
    {
        $ks = new KeyStore(['id' => 'secret']);
        $key = $ks->fetch('nope');
    }
}
