<?php
require __DIR__ . '/../../config/config.php'; // Database configuration


if (!isset($_GET['token'])) {
  die("Invalid or missing token.");
}

// Redirect if the user is not logged in
if (!isset($_SESSION['user_id'])) {
  header('Location: login.php');
  exit;
}

$reset_token = htmlspecialchars($_GET['token']); // Token passed via URL
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

$errorMessage = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  $resetToken = $_POST['reset_token'];
  $password = $_POST['password'];
  $confirmPassword = $_POST['confirm_password'];

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

        echo "Password has been successfully reset. <a href='login.php'>Login here</a>.";
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
?>