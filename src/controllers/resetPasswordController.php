<?php
session_start(); // Ensure session is started

require __DIR__ . '/../../config/config.php'; // Database configuration

$reset_token = $_GET['token'] ?? $_POST['reset_token'] ?? null;
if (!$reset_token) {
    die("Invalid or missing reset token.");
}

// Generate CSRF token only if it doesn't exist
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

$errorMessage = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $resetToken = $_POST['reset_token'];
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];
    $csrfToken = $_POST['csrf_token'];

    // CSRF token validation
    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        die("Invalid CSRF token.");
    }

    if (empty($resetToken)) {
        $errorMessage = 'Invalid or missing reset token.';
    } elseif ($password !== $confirmPassword) {
        $errorMessage = 'Passwords do not match.';
    } elseif (!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password)) {
        $errorMessage = 'Password must be at least 8 characters long, include an uppercase letter, a number, and a special character.';
    } else {
        try {
            // Verify token and expiry
            $stmt = $pdo->prepare("SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()");
            $stmt->execute([$resetToken]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // Hash the new password
                $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

                // Update password and clear token
                $stmt = $pdo->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?");
                $stmt->execute([$hashedPassword, $user['id']]);

                header('Location: login.php?message=Password reset successfully');
                exit;
            } else {
                $errorMessage = 'Invalid or expired reset token.';
            }
        } catch (PDOException $e) {
            error_log("Database error during password reset: " . $e->getMessage());
            $errorMessage = 'Something went wrong. Please try again later.';
        }
    }
}