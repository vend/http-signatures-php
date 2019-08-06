<?php
require './vendor/autoload.php';

$psr17Factory = new \Nyholm\Psr7\Factory\Psr17Factory();
$psr18Client = new \Buzz\Client\Curl($psr17Factory);

function initializeRequest($refRequest) {
    global $psr17Factory;
    $refMethod = explode(' ',$refRequest[0])[0];
    $request = new Nyholm\Psr7\Request(
      explode(' ',$refRequest[0])[0],
      'http://localhost:6789'
    );

    $refUri = explode(' ',$refRequest[0])[1];
    $refPath = explode('?',$refUri)[0];
    $refQry = explode('?',$refUri)[1];
    $reqUri = $request->getUri()
        ->withPath($refPath)
        ->withQuery($refQry);
    $request = $request->withUri($reqUri);
    $requestBody = "";
    $lineNumber = 1;
    while ( $lineNumber < sizeof($refRequest) ) {
      $line = trim($refRequest[$lineNumber]);
      if ( $line == "" ) { break; };
      $headerName = explode(':', $line)[0];
      $headerValue = trim(explode(' ',$line,2)[1]);
      $request = $request->withHeader($headerName,$headerValue);
      $lineNumber++;
    };
    $lineNumber++;
    $inBody = false;
    while ( $lineNumber < sizeof($refRequest) ) {
      if ( $inBody ) { $requestBody = $requestBody . "\n"; };
      $inBody = true;
      $requestBody = $requestBody . $refRequest[$lineNumber];
      $lineNumber++;
    };
    return $request ->withBody($psr17Factory->createStream($requestBody));
}
$refRequestFile = file(__DIR__ . '/../request.http');
$referencePrivateKeyFile = file_get_contents(__DIR__ . '/../keys/Test-private.pem');
$referencePrivateKey = ['Test' => $referencePrivateKeyFile];
$referenceRequest = initializeRequest($refRequestFile);

print "==================================================" . PHP_EOL;
print "Signing HTTP Messages v10 Reference Implementation" . PHP_EOL;
print "==================================================" . PHP_EOL;
print "Using Reference Request:--------------------------" . PHP_EOL;
foreach ($refRequestFile as $line) {
  print $line;
};
print PHP_EOL;
print "--------------------------------------------------" . PHP_EOL;
print "Using Private Key:--------------------------------" . PHP_EOL;
print $referencePrivateKeyFile;
print "--------------------------------------------------" . PHP_EOL;

// Default Test
// @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.1
print "Default Test:-------------------------------------" . PHP_EOL;
$defaultTestContext = new \HttpSignatures\Context([
  'keys' => $referencePrivateKey,
  'algorithm' => 'rsa-sha256'
]);
$signedRequest = $defaultTestContext->signer()->sign($referenceRequest);
$expectedSignatureHeaderValue = trim(file_get_contents(__DIR__ . '/../headers/default-test-signature'));
if (
  $signedRequest->getHeader('Signature')[0] ==
  $expectedSignatureHeaderValue
) {
  print "Signature header correctly generated: '$expectedSignatureHeaderValue'" . PHP_EOL;
} else {
  print "Signature header NOT correctly generated: '$expectedSignatureHeaderValue'" . PHP_EOL;
};
$response = $psr18Client->sendRequest($signedRequest);
$resonseObject = json_decode((string)$response->getBody());
if ($resonseObject->signatures->Signature) {
    print "Server reports Signature header validated" . PHP_EOL;
} else {
    print "Server reports Signature header NOT validated !!!!!!!!!!!" . PHP_EOL;
};
print "--------------------------------------------------" . PHP_EOL;

$authorizedRequest = $defaultTestContext->signer()->authorize($referenceRequest);
$expectedAuthorizationHeaderValue = trim(file_get_contents(__DIR__ . '/../headers/default-test-authorization'));
if (
    $authorizedRequest->getHeader('Authorization')[0] ==
    $expectedAuthorizationHeaderValue
) {
    print "Authorization header correctly generated: '$expectedAuthorizationHeaderValue'" . PHP_EOL;
  } else {
    print "Authorization header NOT correctly generated: '$expectedAuthorizationHeaderValue'" . PHP_EOL;
  };
$response = $psr18Client->sendRequest($authorizedRequest);
$resonseObject = json_decode((string)$response->getBody());
if ($resonseObject->signatures->Authorization) {
    print "Server reports Authorization header validated" . PHP_EOL;
} else {
    print "Server reports Authorization header NOT validated !!!!!!!!!!!" . PHP_EOL;
};
print "--------------------------------------------------" . PHP_EOL;
