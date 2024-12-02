<?php
require __DIR__ . '/../../config/config.php'; // Include the database configuration

$errorMessage = ''; // Initialize an error message variable

// Process the form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  // Get form data and sanitize/validate it
  $name = htmlspecialchars(trim($_POST['name']));
  $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
  $password = $_POST['password'];
  $contact = htmlspecialchars(trim($_POST['contact']));

  // Validate inputs
  if (!preg_match('/^[a-zA-Z\s]+$/', $name)) {
    $errorMessage = 'Name must only contain letters and spaces';
  } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errorMessage = 'Invalid email address';
  } elseif (!preg_match('/^\d{10}$/', $contact)) {
    $errorMessage = 'Contact number must be exactly 10 digits';
  } elseif (!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password)) {
    $errorMessage = 'Password must be at least 8 characters long, include an uppercase letter, a number, and a special character.';
  }

  // If no errors, proceed with registration
  if (empty($errorMessage)) {
    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    try {
      // Insert into database
      $stmt = $pdo->prepare("INSERT INTO users (name, email, password, contact_number) VALUES (?, ?, ?, ?)");
      $stmt->execute([$name, $email, $hashedPassword, $contact]);

      // Redirect to login page after successful registration
      header('Location: login.php');
      exit; // Ensure no further code is executed
    } catch (PDOException $e) {
      // Handle duplicate email error (23000 is the code for duplicate entry)
      if ($e->getCode() == 23000) {
        $errorMessage = "Email already exists. Please choose another one.";
      } else {
        // Log the error and provide a generic error message
        error_log("Database error: " . $e->getMessage());
        $errorMessage = "Something went wrong. Please try again later.";
      }
    }
  }
}
?>