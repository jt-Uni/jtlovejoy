<?php
require __DIR__ . '/../../config/config.php'; // Include the database configuration

$errorMessage = ''; // Initialize an error message variable

// Process the form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get form data and sanitize/validate it
    $name = htmlspecialchars($_POST['name']);
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $contact = htmlspecialchars($_POST['contact']);
    
    // Validate inputs
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorMessage = 'Invalid email address';
    } elseif (strlen($password) < 8) {
        $errorMessage = 'Password must be at least 8 characters';
    } elseif (!preg_match('/^[0-9]+$/', $contact)) {
        $errorMessage = 'Invalid contact number';
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
                $errorMessage = "Error: " . $e->getMessage();
            }
        }
    }
}
?>