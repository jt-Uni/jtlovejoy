<?php
session_start();
require __DIR__ . '/../../config/config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $recaptchaSecret = $_ENV['RECAPTCHA_SECRET']; // Replace with your reCAPTCHA secret key
  $recaptchaResponse = $_POST['g-recaptcha-response'];

  // Verify the token with Google reCAPTCHA
  $response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$recaptchaSecret&response=$recaptchaResponse");
  $responseKeys = json_decode($response, true);

  if (!$responseKeys["success"]) {
    $errorMessage = "reCAPTCHA verification failed. Please try again.";
  } else {
    // Continue with login validation
    $email = $_POST['email'];
    $password = $_POST['password'];

    try {
      // Fetch user details including 'role'
      $stmt = $pdo->prepare("SELECT id, name, role, password FROM users WHERE email = ?");
      $stmt->execute([$email]);
      $user = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($user && password_verify($password, $user['password'])) {
        // Store user information in session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['name'] = $user['name'];
        $_SESSION['role'] = $user['role'];

        header('Location: dashboard.php');
        exit; // Prevent further code execution
      } else {
        $errorMessage = "Invalid email or password.";
      }
    } catch (PDOException $e) {
      error_log("Database error during login: " . $e->getMessage());
      $errorMessage = "Something went wrong. Please try again later.";
    }
  }
}
?>
