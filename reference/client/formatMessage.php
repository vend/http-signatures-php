<?php

function formatMessage($refRequest) {
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
