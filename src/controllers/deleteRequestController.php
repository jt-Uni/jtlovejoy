<?php
session_start();
require __DIR__ . '/../../config/config.php';

if ($_SESSION['role'] !== 'admin') {
  die("Access denied. Admins only.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $request_id = $_POST['request_id'];

  try {
    $stmt = $pdo->prepare("SELECT photo FROM evaluation_requests WHERE id = ?");
    $stmt->execute([$request_id]);
    $request = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($request) {
      $stmt = $pdo->prepare("DELETE FROM evaluation_requests WHERE id = ?");
      $stmt->execute([$request_id]);

      $photo_path = __DIR__ . '/../../uploads/' . $request['photo'];
      if (file_exists($photo_path)) {
        unlink($photo_path);
      }

      header("Location: ../views/adminRequests.php");
      exit;
    } else {
      die("Request not found.");
    }
  } catch (PDOException $e) {
    error_log("Database error deleting request: " . $e->getMessage());
    die("Error deleting the request.");
  }
}
?>