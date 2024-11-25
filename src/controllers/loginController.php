<?php
require __DIR__ . '/../../config/config.php'; // Include the database configuration
session_start(); // Start a session to store user data upon successful login

// Check if the user is already logged in (redirect to dashboard if true)
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

// Initialize error message variable
$errorMessage = '';

// Process the form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize and validate inputs
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $password = trim($_POST['password']);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorMessage = 'Invalid email address';
    }

    // Proceed if no validation errors
    if (empty($errorMessage)) {
        try {
            // Query to fetch user by email
            $stmt = $pdo->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                // Login successful: Store user info in session securely
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = htmlspecialchars($user['name']);
                $_SESSION['user_email'] = htmlspecialchars($user['email']);

                // Redirect to dashboard or home page after successful login
                header('Location: dashboard.php');
                exit;
            } else {
                $errorMessage = 'Invalid email or password';
            }
        } catch (PDOException $e) {
            // Log the error and display a generic message
            error_log("Database error during login: " . $e->getMessage());
            $errorMessage = "Something went wrong. Please try again later.";
        }
    }
}
?>
