<?php
require("vendor/autoload.php");

$openapi = \OpenApi\Generator::scan([__DIR__ . '/api/']);

header('Content-Type: application/json');
echo $openapi->toJson();