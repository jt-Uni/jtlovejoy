<?php
session_start();

if (!isset($_SESSION['user_id'])) {
  header('Location: login.php');
  exit;
}

require __DIR__ . '/../../config/config.php';

$userId = $_SESSION['user_id'];

$errorMessage = '';
$successMessage = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  $name = trim(htmlspecialchars($_POST['name']));
  $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
  $contact = trim(htmlspecialchars($_POST['contact']));

  if (empty($name)) {
    $errorMessage = 'Name cannot be empty.';
  } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errorMessage = 'Invalid email address.';
  } elseif (!preg_match('/^[0-9]+$/', $contact)) {
    $errorMessage = 'Contact number must contain only digits.';
  }

  if (empty($errorMessage)) {
    try {
      $stmt = $pdo->prepare("UPDATE users SET name = ?, email = ?, contact_number = ? WHERE id = ?");
      $stmt->execute([$name, $email, $contact, $userId]);

      $successMessage = 'Profile updated successfully!';
    } catch (PDOException $e) {
      if ($e->getCode() == 23000) {
        $errorMessage = 'Email address is already in use.';
      } else {
        error_log("Error updating profile: " . $e->getMessage());
        $errorMessage = 'An unexpected error occurred. Please try again later.';
      }
    }
  }
}

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
  die('An error occurred while loading your profile. Please try again later.');
}
?>