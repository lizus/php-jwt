<?php
include '../vendor/autoload.php';
include 'JWT.php';

$a=JWT::encode(['uid'=>1,'exp'=>time()+86400*7]);
var_dump($a);
var_dump(JWT::decode($a));