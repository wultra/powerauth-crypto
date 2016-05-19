<?php

require_once __DIR__ . "/header.php";
require_once __DIR__ . "/texy.php";

$texy = new Texy();
$text = file_get_contents(__DIR__ . '/data/terms.md');

$html = $texy->process($text);

echo $html;

require_once __DIR__ . "/footer.php";