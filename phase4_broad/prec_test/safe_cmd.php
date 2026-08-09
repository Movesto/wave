<?php $x = $_POST['c']; echo shell_exec("ls " . escapeshellarg($x)); ?>
