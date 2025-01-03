<?php
session_start();
require __DIR__ . '/../../config/config.php';

if (!isset($_SESSION['user_id'])) {
  header('Location: login.php');
  exit;
}

if (!isset($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errorMessage = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

  if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("CSRF token validation failed.");
  }
  unset($_SESSION['csrf_token']);

  $comment = htmlspecialchars(trim($_POST['comment']));
  $contact_method = htmlspecialchars(trim($_POST['contact_method']));
  $user_id = $_SESSION['user_id'];

  if (!empty($_FILES['photo']['name'])) {
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($_FILES['photo']['type'], $allowed_types)) {
      $errorMessage = "Invalid file type. Only JPEG, PNG, and GIF are allowed.";
    } elseif ($_FILES['photo']['size'] > 5 * 1024 * 1024) {
      $errorMessage = "File size exceeds the 5MB limit.";
    } else {
      $upload_dir = __DIR__ . '/../../uploads/';
      $file_name = uniqid() . '_' . basename($_FILES['photo']['name']);
      $upload_path = $upload_dir . $file_name;

      if (!move_uploaded_file($_FILES['photo']['tmp_name'], $upload_path)) {
        $errorMessage = "Failed to upload the file.";
      }
    }
  }

  if (empty($errorMessage)) {
    try {
      $stmt = $pdo->prepare("INSERT INTO evaluation_requests (user_id, comment, contact_method, photo) VALUES (?, ?, ?, ?)");
      $stmt->execute([$user_id, $comment, $contact_method, $file_name]);

      header('Location: dashboard.php?success=1');
      exit;
    } catch (PDOException $e) {
      error_log("Database error during evaluation request: " . $e->getMessage());
      $errorMessage = "Something went wrong. Please try again later.";
    }
  }
}
?>