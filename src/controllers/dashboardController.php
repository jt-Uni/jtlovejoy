<?php
session_start();

require __DIR__ . '/../../config/config.php';

if (!isset($_SESSION['user_id'])) {
  header('Location: login.php');
  exit;
}

$userId = $_SESSION['user_id'];

try {
  $stmt = $pdo->prepare("SELECT name, email, contact_number FROM users WHERE id = ?");
  $stmt->execute([$userId]);
  $user = $stmt->fetch(PDO::FETCH_ASSOC);

  if (!$user) {
    session_destroy();
    header('Location: login.php');
    exit;
  }
} catch (PDOException $e) {
  error_log("Error fetching user data: " . $e->getMessage());
  die("An error occurred. Please try again later.");
}
?>