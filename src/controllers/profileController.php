<?php
session_start(); // Start the session

// Check if the user is logged in, if not, redirect to the login page
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require __DIR__ . '/../../config/config.php'; // Include the database configuration

// Fetch the user's ID from the session
$userId = $_SESSION['user_id'];

// Initialize variables for messages
$errorMessage = '';
$successMessage = '';

// Handle profile update submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize and validate user input
    $name = trim(htmlspecialchars($_POST['name']));
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $contact = trim(htmlspecialchars($_POST['contact']));

    // Validate inputs
    if (empty($name)) {
        $errorMessage = 'Name cannot be empty.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorMessage = 'Invalid email address.';
    } elseif (!preg_match('/^[0-9]+$/', $contact)) {
        $errorMessage = 'Contact number must contain only digits.';
    }

    // If validation passes, update user information
    if (empty($errorMessage)) {
        try {
            $stmt = $pdo->prepare("UPDATE users SET name = ?, email = ?, contact_number = ? WHERE id = ?");
            $stmt->execute([$name, $email, $contact, $userId]);
            
            // Set success message
            $successMessage = 'Profile updated successfully!';
        } catch (PDOException $e) {
            // Check for duplicate email constraint
            if ($e->getCode() == 23000) {
                $errorMessage = 'Email address is already in use.';
            } else {
                error_log("Error updating profile: " . $e->getMessage());
                $errorMessage = 'An unexpected error occurred. Please try again later.';
            }
        }
    }
}

// Fetch the user's current data
try {
    $stmt = $pdo->prepare("SELECT name, email, contact_number FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Invalid session or user not found
        session_destroy();
        header('Location: login.php');
        exit;
    }
} catch (PDOException $e) {
    error_log("Error fetching user data: " . $e->getMessage());
    die('An error occurred while loading your profile. Please try again later.');
}
?>
