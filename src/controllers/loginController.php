<?php
require __DIR__ . '/../../config/config.php'; // Include the database configuration
session_start(); // Start a session to store user data upon successful login

// Check if the user is already logged in (redirect to home or dashboard if true)
if (isset($_SESSION['user_id'])) {
  header('Location: dashboard.php');
  exit;
}

// Process the form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  // Get form data
  $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
  $password = $_POST['password'];

  // Validate inputs
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errorMessage = 'Invalid email address';
  }

  // Check if the user exists in the database
  if (!isset($errorMessage)) {
    try {
      // Prepare SQL query to fetch user by email
      $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
      $stmt->execute([$email]);
      $user = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($user && password_verify($password, $user['password'])) {
        // Login successful: Store user info in session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_name'] = $user['name'];
        $_SESSION['user_email'] = $user['email'];

        // Redirect to dashboard or home page after successful login
        header('Location: dashboard.php');
        exit;
      } else {
        $errorMessage = 'Invalid email or password';
      }
    } catch (PDOException $e) {
      $errorMessage = "Error: " . $e->getMessage();
    }
  }
}
?>