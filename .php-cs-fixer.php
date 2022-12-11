<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__ . "/src")
    ->in(__DIR__ . "/tests");

return (new PhpCsFixer\Config())
    ->setRules([
        '@PSR2' => true,
        '@Symfony' => true,
    ])
    ->setFinder($finder)
;
