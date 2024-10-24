<?php
// Actual database connection
$db = new mysqli('localhost', 'root', '7503', 'phpvuln');

if ($db->connect_error) {
    die("Connection failed: " . $db->connect_error);
}

// 1. SQL Injection
function vulnerable_login($username, $password) {
    global $db;
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $db->query($query);
    
    if ($result === false) {
        return "Error: " . $db->error;
    }
    
    // Fetch the results
    $rows = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();
    
    // Prepare the response
    $response = "Query: " . $query . "\n\n";
    $response .= "Results:\n" . print_r($rows, true) . "\n\n";
    
    if (count($rows) > 0) {
        $response .= "Login successful. Found " . count($rows) . " matching user(s).";
    } else {
        $response .= "Login failed";
    }
    
    return $response;
}

function safe_login($username, $password) {
    global $db;
    $query = "SELECT * FROM users WHERE username = ? AND password = ?";
    $stmt = $db->prepare($query);
    if ($stmt === false) {
        return "Error preparing statement: " . $db->error;
    }
    
    $stmt->bind_param("ss", $username, $password);
    if (!$stmt->execute()) {
        return "Error executing statement: " . $stmt->error;
    }
    
    $result = $stmt->get_result();
    $rows = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    
    // Prepare the response
    $response = "Query: " . $query . "\n";
    $response .= "Bound parameters: username = '$username', password = '$password'\n\n";
    $response .= "Results:\n" . print_r($rows, true) . "\n\n";
    
    if (count($rows) > 0) {
        $response .= "Login successful";
    } else {
        $response .= "Login failed";
    }
    
    return $response;
}

// The rest of the code remains the same...

// 2. XSS (unchanged)
function vulnerable_display_message($message) {
    echo "<div>$message</div>";
}

function safe_display_message($message) {
    echo "<div>" . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . "</div>";
}

// 3. Directory Traversal (unchanged)
function vulnerable_get_file($filename) {
    $file_path = "/var/www/files/" . $filename;
    return file_get_contents($file_path);
}

function safe_get_file($filename) {
    $allowed_dir = "/var/www/files/";
    $real_path = realpath($allowed_dir . $filename);
    if ($real_path === false || strpos($real_path, $allowed_dir) !== 0) {
        return "Access denied";
    }
    return file_get_contents($real_path);
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $vulnerability = $_POST['vulnerability'];
    $is_vulnerable = $_POST['is_vulnerable'] === 'true';

    switch ($vulnerability) {
        case 'sql_injection':
            $username = $_POST['username'];
            $password = $_POST['password'];
            $result = $is_vulnerable ? vulnerable_login($username, $password) : safe_login($username, $password);
            echo json_encode(['result' => nl2br($result)]);
            break;
        
        case 'xss':
            $message = $_POST['message'];
            ob_start();
            $is_vulnerable ? vulnerable_display_message($message) : safe_display_message($message);
            echo json_encode(['result' => ob_get_clean()]);
            break;
        
        case 'directory_traversal':
            $filename = $_POST['filename'];
            $result = $is_vulnerable ? vulnerable_get_file($filename) : safe_get_file($filename);
            echo json_encode(['result' => $result]);
            break;
    }
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable PHP Application (with Fixes)</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }
        h1, h2 { color: #333; }
        .vulnerability { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; }
        .result { margin-top: 10px; padding: 10px; background-color: #f0f0f0; white-space: pre-wrap; }
        button { margin-top: 10px; }
    </style>
</head>
<body>
    <h1>Vulnerable PHP Application (with Fixes)</h1>
    
    <div class="vulnerability">
        <h2>1. SQL Injection</h2>
        <input type="text" id="sql_username" placeholder="Username">
        <input type="password" id="sql_password" placeholder="Password">
        <button onclick="testVulnerability('sql_injection', true)">Test Vulnerable</button>
        <button onclick="testVulnerability('sql_injection', false)">Test Safe</button>
        <div id="sql_injection_result" class="result"></div>
    </div>
    
    <div class="vulnerability">
        <h2>2. Cross-Site Scripting (XSS)</h2>
        <input type="text" id="xss_message" placeholder="Enter a message">
        <button onclick="testVulnerability('xss', true)">Test Vulnerable</button>
        <button onclick="testVulnerability('xss', false)">Test Safe</button>
        <div id="xss_result" class="result"></div>
    </div>
    
    <div class="vulnerability">
        <h2>3. Directory Traversal</h2>
        <input type="text" id="dt_filename" placeholder="Enter a filename">
        <button onclick="testVulnerability('directory_traversal', true)">Test Vulnerable</button>
        <button onclick="testVulnerability('directory_traversal', false)">Test Safe</button>
        <div id="directory_traversal_result" class="result"></div>
    </div>

    <script>
    function testVulnerability(vulnerability, isVulnerable) {
        let data = {
            vulnerability: vulnerability,
            is_vulnerable: isVulnerable
        };

        switch(vulnerability) {
            case 'sql_injection':
                data.username = $('#sql_username').val();
                data.password = $('#sql_password').val();
                break;
            case 'xss':
                data.message = $('#xss_message').val();
                break;
            case 'directory_traversal':
                data.filename = $('#dt_filename').val();
                break;
        }

        $.post('', data, function(response) {
            let result = JSON.parse(response).result;
            $(`#${vulnerability}_result`).html(result);
        });
    }
    </script>
</body>
</html>