<?php
session_start(); // Start the session

require __DIR__ . '/../../config/config.php'; // Include the database configuration

// Redirect to login page if the user is not logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Fetch the user's data from the database using the session user_id
$userId = $_SESSION['user_id'];

try {
    $stmt = $pdo->prepare("SELECT name, email, contact_number FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Handle invalid session case where user ID no longer exists
        session_destroy();
        header('Location: login.php');
        exit;
    }
} catch (PDOException $e) {
    // Log the error and display a generic error message
    error_log("Error fetching user data: " . $e->getMessage());
    die("An error occurred. Please try again later.");
}
?>
