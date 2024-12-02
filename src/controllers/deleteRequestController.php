<?php
session_start();
require __DIR__ . '/../../config/config.php';

// Check if the user is an admin
if ($_SESSION['role'] !== 'admin') {
  die("Access denied. Admins only.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $request_id = $_POST['request_id'];

  try {
    // Fetch the photo filename for deletion
    $stmt = $pdo->prepare("SELECT photo FROM evaluation_requests WHERE id = ?");
    $stmt->execute([$request_id]);
    $request = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($request) {
      // Delete the record from the database
      $stmt = $pdo->prepare("DELETE FROM evaluation_requests WHERE id = ?");
      $stmt->execute([$request_id]);

      // Delete the photo file
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