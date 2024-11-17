<?php
session_start(); // Start the session

// Check if the user is logged in, if not, redirect to the login page
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require __DIR__ . '/../../config/config.php'; // Include the database configuration

// Fetch the user's data from the database using the session user_id
$userId = $_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get form data and sanitize/validate it
    $name = htmlspecialchars($_POST['name']);
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $contact = htmlspecialchars($_POST['contact']);

    // Validate inputs
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorMessage = 'Invalid email address';
    }
    if (!preg_match('/^[0-9]+$/', $contact)) {
        $errorMessage = 'Invalid contact number';
    }

    // Update user information in the database
    try {
        $stmt = $pdo->prepare("UPDATE users SET name = ?, email = ?, contact_number = ? WHERE id = ?");
        $stmt->execute([$name, $email, $contact, $userId]);
        
        // Success message or redirect after successful update
        $successMessage = 'Profile updated successfully!';
    } catch (PDOException $e) {
        $errorMessage = 'Error updating profile: ' . $e->getMessage();
    }
}

// Fetch updated user data
try {
    $stmt = $pdo->prepare("SELECT name, email, contact_number FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $user = $stmt->fetch();
} catch (PDOException $e) {
    die("Error fetching user data: " . $e->getMessage());
}

?>