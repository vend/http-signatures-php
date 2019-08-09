<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\HeaderList;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use HttpSignatures\SigningString;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use PHPUnit\Framework\TestCase;

class SigningStringTest extends TestCase
{
    public function setUp()
    {
        $this->message = new Request(
          'GET',
          '/path',
          ['date' => 'Mon, 28 Jul 2014 15:39:13 -0700']
        );
        $this->psr7Factory = new DiactorosFactory();
    }

    public function testWithoutQueryString()
    {
        $headerList = new HeaderList(['(request-target)']);
        $ss = new SigningString($headerList, $this->message);

        $this->assertEquals(
            '(request-target): get /path',
            $ss->string()
        );
    }

    public function testSigningStringWithOrderedQueryParameters()
    {
        $headerList = new HeaderList(['(request-target)', 'date']);
        $uri = $this->message->getUri()->withQuery('a=antelope&z=zebra');
        $ss = new SigningString(
          $headerList,
          $this->message->withUri($uri)
        );

        $this->assertEquals(
            "(request-target): get /path?a=antelope&z=zebra\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    public function testSigningStringWithUnorderedQueryParameters()
    {
        $headerList = new HeaderList(['(request-target)', 'date']);
        $uri = $this->message->getUri()->withQuery('z=zebra&a=antelope');
        $ss = new SigningString(
          $headerList,
          $this->message->withUri($uri)
        );

        $this->assertEquals(
            "(request-target): get /path?z=zebra&a=antelope\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    public function testSigningStringWithOrderedQueryParametersSymfonyRequest()
    {
        $headerList = new HeaderList(['(request-target)', 'date']);
        $ss = new SigningString($headerList, $this->symfonyMessage('/path?a=antelope&z=zebra'));

        $this->assertEquals(
            "(request-target): get /path?a=antelope&z=zebra\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    public function testSigningStringWithUnorderedQueryParametersSymfonyRequest()
    {
        $headerList = new HeaderList(['(request-target)', 'date']);
        $ss = new SigningString($headerList, $this->symfonyMessage('/path?z=zebra&a=antelope'));

        $this->assertEquals(
            "(request-target): get /path?z=zebra&a=antelope\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    public function testSigningStringErrorForMissingHeader()
    {
        $headerList = new HeaderList(['nope']);
        $uri = $this->message->getUri()->withPath('/');

        $ss = new SigningString(
          $headerList,
          $this->message->withUri($uri)
        );
        $this->expectException(\HttpSignatures\Exception::class);
        $ss->string();
    }

    private function symfonyMessage($path)
    {
        $symfonyRequest = SymfonyRequest::create($path, 'GET');
        $symfonyRequest->headers->replace(['date' => 'Mon, 28 Jul 2014 15:39:13 -0700']);

        $psrRequest = $this->psr7Factory
          ->createRequest($symfonyRequest)
          ->withRequestTarget($symfonyRequest
          ->getRequestUri());

        return $psrRequest;
    }

    public function testDuplicateHeader()
    {
        $headerList = new HeaderList(['date']);
        $message = $this->message->withAddedHeader('Date', 'another date');
        $ss = new SigningString($headerList, $message);

        $this->assertEquals(
            'date: Mon, 28 Jul 2014 15:39:13 -0700, another date',
            $ss->string()
        );
    }

    public function testEmptyHeaders()
    {
        // Not cryptographically useful, but strictly required.
        $headerList = new HeaderList([]);
        $ss = new SigningString($headerList, $this->message);

        $this->assertEquals(
            '',
            $ss->string()
        );
    }
}
