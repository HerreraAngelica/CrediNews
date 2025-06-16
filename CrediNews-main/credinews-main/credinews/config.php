<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'credinews');

// Application settings
define('APP_NAME', 'CrediNews');
define('APP_URL', 'http://localhost/credinews');
define('EMAIL_FROM', 'noreply@credinews.com');

// Security settings
define('ENCRYPTION_KEY', 'your_secure_encryption_key_here'); // Change this in production
define('HASH_ALGORITHM', 'sha256');

// Rate limiting settings
define('MAX_SUBMISSIONS_PER_DAY', 5);
define('SUBMISSION_TIMEOUT', 3600); // 1 hour in seconds

// Connect to database
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Start session if not already started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Helper functions

// Encrypt data
function encryptData($data) {
    $method = "AES-256-CBC";
    $key = hash('sha256', ENCRYPTION_KEY, true);
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, $method, $key, 0, $iv);
    return base64_encode($encrypted . '::' . $iv);
}

// Decrypt data
function decryptData($data) {
    $method = "AES-256-CBC";
    $key = hash('sha256', ENCRYPTION_KEY, true);
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, $method, $key, 0, $iv);
}

// Generate digital signature for reports
function generateSignature($data) {
    return hash(HASH_ALGORITHM, $data . ENCRYPTION_KEY);
}

// Verify digital signature
function verifySignature($data, $signature) {
    return hash(HASH_ALGORITHM, $data . ENCRYPTION_KEY) === $signature;
}

// Log user actions
function logAction($userId, $action, $entityType = null, $entityId = null) {
    global $conn;
    $ip = $_SERVER['REMOTE_ADDR'];
    $stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action, entity_type, entity_id, ip_address) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("issss", $userId, $action, $entityType, $entityId, $ip);
    $stmt->execute();
    $stmt->close();
}

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

// Check user role
function hasRole($role) {
    return isset($_SESSION['user_role']) && $_SESSION['user_role'] === $role;
}

// Check if user is admin or reviewer
function isAdminOrReviewer() {
    return isset($_SESSION['user_role']) && ($_SESSION['user_role'] === 'admin' || $_SESSION['user_role'] === 'reviewer');
}

// Redirect with message
function redirect($url, $message = '', $type = 'info') {
    if (!empty($message)) {
        $_SESSION['message'] = $message;
        $_SESSION['message_type'] = $type;
    }
    header("Location: $url");
    exit();
}
?>