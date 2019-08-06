<?php
require __DIR__ . '/../../vendor/autoload.php';

$referencePublicKey = ['Test' => file_get_contents(__DIR__ . '/../keys/Test-public.pem')];

$verifierContext = new \HttpSignatures\Context([
  'keys' => $referencePublicKey
]);

$psr17Factory = new \Nyholm\Psr7\Factory\Psr17Factory();

$creator = new \Nyholm\Psr7Server\ServerRequestCreator(
    $psr17Factory, // ServerRequestFactory
    $psr17Factory, // UriFactory
    $psr17Factory, // UploadedFileFactory
    $psr17Factory  // StreamFactory
);

$body = [];
$serverRequest = $creator->fromGlobals();

if ( $serverRequest->getHeader('Signature') ) {
    $body['headers']['Signature'] = $serverRequest->getHeader('Signature')[0];
}
if ( $serverRequest->getHeader('Authorization') ) {
  $body['headers']['Authorization'] = $serverRequest->getHeader('Authorization')[0];
}

$body['signatures']['Authorization'] = $verifierContext->verifier()->isAuthorized($serverRequest);
$body['signatures']['Signature'] = $verifierContext->verifier()->isSigned($serverRequest);

$responseBody = $psr17Factory->createStream(json_encode($body));
$response = $psr17Factory->createResponse(200)
  ->withBody($responseBody);
(new \Zend\HttpHandlerRunner\Emitter\SapiEmitter())->emit($response);

?>
