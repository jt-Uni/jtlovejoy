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

try {
  $stmt = $pdo->prepare("SELECT name, email, contact_number FROM users WHERE id = ?");
  $stmt->execute([$userId]);
  $user = $stmt->fetch();

  if (!$user) {
    // If no user found (which shouldn't happen if session is valid)
    die('User not found.');
  }

} catch (PDOException $e) {
  die("Error fetching user data: " . $e->getMessage());
}

?>